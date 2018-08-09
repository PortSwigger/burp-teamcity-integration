package net.portswigger.burp.api.teamcity;

import jetbrains.buildServer.requirements.Requirement;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.serverSide.RunType;
import jetbrains.buildServer.serverSide.RunTypeRegistry;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static net.portswigger.burp.api.teamcity.BurpScanConstants.*;

public class AppServer
{
    public AppServer (PluginDescriptor descriptor, RunTypeRegistry runTypeRegistry)
    {
        runTypeRegistry.registerRunType(new BurpScan(descriptor));
    }

    private static class BurpScan extends RunType
    {
        private final PluginDescriptor descriptor;

        public BurpScan(PluginDescriptor descriptor)
        {
            this.descriptor = descriptor;
        }

        @NotNull
        @Override
        public String getType()
        {
            return BurpScanConstants.BURP_SCAN_RUN_TYPE;
        }

        @NotNull
        @Override
        public String getDisplayName()
        {
            return BurpScanConstants.BURP_SCAN_RUN_TYPE_DISPLAY_NAME;
        }

        @NotNull
        @Override
        public String getDescription()
        {
            return BurpScanConstants.BURP_SCAN_RUN_TYPE_DESCRIPTION;
        }

        @Nullable
        @Override
        public PropertiesProcessor getRunnerPropertiesProcessor()
        {
            return PROPERTIES_VALIDATOR;
        }

        @Nullable
        @Override
        public String getEditRunnerParamsJspFilePath()
        {
            return descriptor.getPluginResourcesPath("Edit.jsp");
        }

        @Nullable
        @Override
        public String getViewRunnerParamsJspFilePath()
        {
            return descriptor.getPluginResourcesPath("View.jsp");
        }

        @Nullable
        @Override
        public Map<String, String> getDefaultRunnerProperties()
        {
            Map<String, String> properties = new HashMap<>();

            properties.put(BURP_SCAN_PROPERTY_API_URL, BURP_SCAN_PROPERTY_API_URL_EMPTY);
            properties.put(BURP_SCAN_PROPERTY_SEVERITY_THRESHOLD, BURP_SCAN_PROPERTY_SEVERITY_THRESHOLD_EMPTY);
            properties.put(BURP_SCAN_PROPERTY_CONFIDENCE_THRESHOLD, BURP_SCAN_PROPERTY_CONFIDENCE_THRESHOLD_EMPTY);

            return properties;
        }

        @NotNull
        @Override
        public List<Requirement> getRunnerSpecificRequirements(@NotNull Map<String, String> runParameters)
        {
            return super.getRunnerSpecificRequirements(runParameters);
        }

        private static final PropertiesProcessor PROPERTIES_VALIDATOR = properties -> Collections.emptyList();
    }

}