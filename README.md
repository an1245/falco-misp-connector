# Falco MISP Connector

## Introduction
The Falco MISP Connector sources indicators from MISP server and consolidates them into a Falco list.  Currently the connector sources IPv4, IPv6, domain name, file hash and URI based indicators from a feed, however only IPv4 indicators are supported in Falco at this time.  

## Prerequisites
The plugin requires the follow items to be configured in *config.py*

**MISP Feed**
- MISP server host name - the host name of the MISP server (ex. osint.digitalside.it)
- MISP server auth key - the API auth key from the MISP Server
- MISP HTTP/HTTPS Setting - does the MISP server use HTTP or HTTPS
- MISP HTTPS Verify Cert - do you want to verify the HTTPS certificate?

**MISP Filtering details**
- MISP Organisation Name - retrieve indicators only from a certain organisation - '' means retrieve from all organisations
- MISP Enforce Warning List - whether to enforce the MISP Warning list - default: true
- MISP Category Filter - comma separated list of MISP categories to retrieve - '' means retrieve from all categories
- MISP Tag Filter - comma separated list of MISP tags to retrieve - '' means retrieve from all tags
- MISP Min Threat Level - minimum threat level to retrieve - use 0 to disable

## How to get started
1. Download code from Git
```
git clone https://github.com/an1245/falco-misp-connector
```

2. Change into directory and set executable bit
```
cd falco-misp-connector
chmod 0700 falco-misp-connector.py
```

3. Install the pre-requisites
```
pip install -r requirements.txt
```

4. Configure your config.py file with your parameters - examples config below:
```
##############################################
#   Falco configuration details              #
##############################################
falco_ipv4_rules_file='/etc/falco/rules.d/misp-ipv4-indicators.yaml'
falco_ipv4_list_name='malicious_ip_list'
falco_domain_rules_file='/etc/falco/rules.d/misp-domain-indicators.yaml'
falco_domain_list_name='malicious_domain_list'

##############################################
#   Debug                                    #
##############################################
debug = True
debugindicators = False
debugyaml = False

##############################################
#   MISP Connectivity Details                #
##############################################
misp_server_url = 'osint.digitalside.it'
misp_is_https = True
misp_auth_key = '{YOUR AUTH KEY}'
misp_verifycert = False

##############################################
#   MISP Filtering Details                   #
##############################################
misp_organisation_name = ''
misp_enforce_warning_list = True
misp_category_filter = ''
misp_tag_filter = ''
misp_min_threat_level = 0
```

5. Execute the connector
```
./falco-misp-connector.py
```

## How can I use these lists in Falco?
You can find some sample Falco rules in the *sample-falco-rules.yaml* file in the GitHub repo - these rules will provide basic inbound/outbound detection of traffic to/from the IPs sourced from the MISP feed.

Copy *sample-falco-rules.yaml* to */etc/falco/rules.d/* directory to initiate these detections.

## Issues / Feedback
- I have done quite a lot of testing, but I am only human, so there may be bugs/errors.
- Please log bugs or give feedback by logging an issue on GitHub
