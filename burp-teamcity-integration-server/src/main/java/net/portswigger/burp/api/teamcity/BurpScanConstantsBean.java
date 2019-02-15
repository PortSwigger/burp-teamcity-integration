package net.portswigger.burp.api.teamcity;

import net.portswigger.burp.api.driver.Confidence;
import net.portswigger.burp.api.driver.Severity;

public class BurpScanConstantsBean
{
    public String getApiUrl()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_API_URL;
    }
    public String getApiUrlEmpty()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_API_URL_EMPTY;
    }

    public String getscanDefinition()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_SCAN_DEFINITION;
    }
    public String getscanDefinitionEmpty()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_SCAN_DEFINITION_EMPTY;
    }

    public String getSeverityThreshold()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_SEVERITY_THRESHOLD;
    }
    public String getSeverityThresholdEmpty()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_SEVERITY_THRESHOLD_EMPTY;
    }

    public String getConfidenceThreshold()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_CONFIDENCE_THRESHOLD;
    }
    public String getConfidenceThresholdEmpty()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_CONFIDENCE_THRESHOLD_EMPTY;
    }

    public String getTimeout()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_TIMEOUT;
    }
    public String getTimeoutEmpty()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_TIMEOUT_EMPTY;
    }

    public String getOutputJsonIssues()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_OUTPUT_JSON_ISSUES;
    }
    public String getOutputJsonIssuesEmpty()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_OUTPUT_JSON_ISSUES_EMPTY;
    }

    public Severity[] getSeverities()
    {
        return Severity.values();
    }

    public Confidence[] getConfidences()
    {
        return Confidence.values();
    }

    public String getSelfSignedCertX509()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_SELF_SIGNED_CERT_X509;
    }
    public String getSelfSignedCertX509Empty()
    {
        return BurpScanConstants.BURP_SCAN_PROPERTY_SELF_SIGNED_CERT_X509_EMPTY;
    }
}
