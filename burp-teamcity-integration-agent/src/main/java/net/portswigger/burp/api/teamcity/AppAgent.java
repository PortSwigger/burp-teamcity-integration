package net.portswigger.burp.api.teamcity;

import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.*;
import jetbrains.buildServer.messages.BuildMessage1;
import jetbrains.buildServer.util.EventDispatcher;
import net.portswigger.burp.api.driver.BurpCiDriver;
import net.portswigger.burp.api.driver.BurpCiSourceConsumer;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.util.*;
import java.util.function.Consumer;

public class AppAgent extends AgentLifeCycleAdapter implements AgentBuildRunner
{
    private static final Logger LOG = Logger.getLogger(AgentLifeCycleAdapter.class);
    private static final int MAX_MESSAGE_CACHE_TIME_MS = 24 * 60 * 60 * 1000;

    private Map<Long, LogLines> relevantBuildMessages = new HashMap<>();

    private static class LogLines
    {
        private Long lastAdded;
        private List<String> messages = new ArrayList<>();

        public void add(String message)
        {
            lastAdded = System.currentTimeMillis();
            messages.add(message);
        }

        public Long getLastAdded()
        {
            return lastAdded;
        }

        public void consume(BurpCiSourceConsumer consumer)
        {
            messages.forEach(consumer::consume);
        }
    }

    public AppAgent(EventDispatcher<AgentLifeCycleListener> agentDispatcher)
    {
        agentDispatcher.addListener(this);
    }

    @Override
    public void messageLogged(@NotNull AgentRunningBuild agentRunningBuild, @NotNull BuildMessage1 buildMessage)
    {
        super.messageLogged(agentRunningBuild, buildMessage);

        Object messageValue = buildMessage.getValue();
        if (messageValue instanceof String)
        {
            String line = (String) messageValue;
            if (line.startsWith("BURP_SCAN_"))
            {
                long key = agentRunningBuild.getBuildId();

                final LogLines lines;
                if (!relevantBuildMessages.containsKey(key))
                {
                    lines = new LogLines();
                    relevantBuildMessages.put(key, lines);
                }
                else
                {
                    lines = relevantBuildMessages.get(key);
                }

                lines.add(line);
            }
        }

        gcRelevantMessages();
    }

    private void gcRelevantMessages()
    {
        long tooOld = System.currentTimeMillis() - MAX_MESSAGE_CACHE_TIME_MS;

        Set<Long> removals = new HashSet<>();
        for (Map.Entry<Long, LogLines> entry : relevantBuildMessages.entrySet())
        {
            if (entry.getValue().getLastAdded() < tooOld)
            {
                removals.add(entry.getKey());
            }
        }

        for (Long buildId : removals)
        {
            relevantBuildMessages.remove(buildId);
        }
    }

    @NotNull
    @Override
    public BuildProcess createBuildProcess(@NotNull AgentRunningBuild agentRunningBuild, @NotNull BuildRunnerContext buildRunnerContext) throws RunBuildException
    {
        try
        {
            BuildProgressLogger logger = agentRunningBuild.getBuildLogger();
            Map<String, String> config = buildRunnerContext.getRunnerParameters();

            BurpCiSourceConsumer burpCiSourceConsumer = new BurpCiSourceConsumer();
            LogLines lines = relevantBuildMessages.get(agentRunningBuild.getBuildId());
            if (lines != null)
            {
                lines.consume(burpCiSourceConsumer);
            }

            Consumer<String> scanningProgress = m -> {
                logger.progressMessage(m);
                logger.progressMessage("Scanning...");
            };

            return new BuildProcess() {
                private volatile Set<Long> issues;
                private volatile Thread thread;

                @Override
                public void start() throws RunBuildException {
                    thread = new Thread(() -> {
                        try {
                            LOG.info("Running Burp scan with config {");
                            for (Map.Entry<String, String> entry : config.entrySet())
                            {
                                LOG.info(String.format("%s = %s", entry.getKey(), entry.getValue()
                                        .replace("\t", "\\t")
                                        .replace("\n", "\\n")
                                        .replace("\r", "\\r")));
                            }
                            LOG.info("}");

                            logger.progressMessage("Running Burp scanner");

                            Set<String> urls = burpCiSourceConsumer.getUrls();
                            for (String url : urls)
                            {
                                logger.progressMessage("Scanning URL: " + url);
                            }

                            issues = new BurpCiDriver(
                                    config.get(BurpScanConstants.BURP_SCAN_PROPERTY_API_URL),
                                    config.get(BurpScanConstants.BURP_SCAN_PROPERTY_SCAN_DEFINITION),
                                    urls,
                                    config.get(BurpScanConstants.BURP_SCAN_PROPERTY_SEVERITY_THRESHOLD),
                                    config.get(BurpScanConstants.BURP_SCAN_PROPERTY_CONFIDENCE_THRESHOLD),
                                    burpCiSourceConsumer.getIgnores(),
                                    null,
                                    null,
                                    "true".equals(config.get(BurpScanConstants.BURP_SCAN_PROPERTY_OUTPUT_JSON_ISSUES))
                                            ? scanningProgress
                                            : null
                            )
                                    .scan(scanningProgress);

                            logger.progressMessage("Finished Burp scan");

                            if (!issues.isEmpty())
                            {
                                logger.progressMessage(String.format("Found %d unexpected issue%s", issues.size(), issues.size() == 1 ? "" : "s"));
                            }
                        } catch (Exception e)
                        {
                            logger.exception(e);
                        }
                    });

                    thread.start();
                }

                @Override
                public boolean isInterrupted()
                {
                    return thread.isInterrupted();
                }

                @Override
                public boolean isFinished()
                {
                    return thread.isAlive();
                }

                @Override
                public void interrupt()
                {
                    thread.interrupt();
                }

                @NotNull
                @Override
                public BuildFinishedStatus waitFor() throws RunBuildException {
                    try {
                        thread.join();

                        return issues == null || !issues.isEmpty()
                                ? BuildFinishedStatus.FINISHED_FAILED
                                : BuildFinishedStatus.FINISHED_SUCCESS;
                    } catch (InterruptedException e)
                    {
                        LOG.info("Thread was interrupted");
                        return BuildFinishedStatus.INTERRUPTED;
                    }
                }
            };
        }
        finally
        {
            relevantBuildMessages.remove(agentRunningBuild.getBuildId());
        }
    }

    private static final AgentBuildRunnerInfo AGENT_BUILD_RUNNER_INFO = new AgentBuildRunnerInfo()
    {
        @NotNull
        @Override
        public String getType()
        {
            return BurpScanConstants.BURP_SCAN_RUN_TYPE;
        }

        @Override
        public boolean canRun(@NotNull BuildAgentConfiguration buildAgentConfiguration)
        {
            return true;
        }
    };

    @NotNull
    @Override
    public AgentBuildRunnerInfo getRunnerInfo()
    {
        return AGENT_BUILD_RUNNER_INFO;
    }
}
