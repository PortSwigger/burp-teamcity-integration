# Burp TeamCity Scan Plugin

TeamCity plugin to scan websites using Burp and fail builds if issues are found.

* Easy configuration to use Burp API to scan fixed or ephemeral websites as part of a TeamCity build configuration
* Configurable thresholds to filter issues to pass/fail builds

### Building
```bash
$ mvn clean package
```
Then the plugin file will be in `target/burp-teamcity-integration.zip`.