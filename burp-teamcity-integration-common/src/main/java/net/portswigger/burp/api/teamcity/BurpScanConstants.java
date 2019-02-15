package net.portswigger.burp.api.teamcity;

import net.portswigger.burp.api.driver.BurpCiDriver;

class BurpScanConstants
{
    static final String BURP_SCAN_RUN_TYPE = "BurpScan";
    static final String BURP_SCAN_RUN_TYPE_DISPLAY_NAME = "Burp scan";
    static final String BURP_SCAN_RUN_TYPE_DESCRIPTION = "Fail the build if Burp finds issues in a website";

    static final String BURP_SCAN_PROPERTY_API_URL = "burpScan.apiUrl";
    static final String BURP_SCAN_PROPERTY_API_URL_EMPTY = "http://burp-api-url:1337/api_key/";

    static final String BURP_SCAN_PROPERTY_SCAN_DEFINITION = "burpScan.scanDefinition";
    static final String BURP_SCAN_PROPERTY_SCAN_DEFINITION_EMPTY = "";

    static final String BURP_SCAN_PROPERTY_SEVERITY_THRESHOLD = "burpScan.severityThreshold";
    static final String BURP_SCAN_PROPERTY_SEVERITY_THRESHOLD_EMPTY = BurpCiDriver.DEFAULT_MIN_SEVERITY;

    static final String BURP_SCAN_PROPERTY_CONFIDENCE_THRESHOLD = "burpScan.confidenceThreshold";
    static final String BURP_SCAN_PROPERTY_CONFIDENCE_THRESHOLD_EMPTY = BurpCiDriver.DEFAULT_MIN_CONFIDENCE;

    static final String BURP_SCAN_PROPERTY_TIMEOUT = "burpScan.timeout";
    static final String BURP_SCAN_PROPERTY_TIMEOUT_EMPTY = BurpCiDriver.DEFAULT_TIMEOUT;

    static final String BURP_SCAN_PROPERTY_OUTPUT_JSON_ISSUES = "burpScan.outputJsonIssues";
    static final String BURP_SCAN_PROPERTY_OUTPUT_JSON_ISSUES_EMPTY = "false";

    static final String BURP_SCAN_PROPERTY_SELF_SIGNED_CERT_X509 = "burpScan.selfSignedCertX509";
    static final String BURP_SCAN_PROPERTY_SELF_SIGNED_CERT_X509_EMPTY = "";
}
