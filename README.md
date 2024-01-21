# Falco MISP Connector

## Introduction
The Falco MISP Connector sources indicators from MISP server and consolidates them into a Falco list.  Currently the connector sources destination IPv4, destination IPv6, domain name, file hash and URI based indicators from a MISP server, however Falco only supports detections using IPv4/IPv6 indicators at this time.  The connector only sources destination IPv4/IPv6 (*ip-dst*) indicators at this time, but it could easily be updated to include source IPv4/IPv6 (*ip-src*) indicators if required.   

## Note Before - Indicator Filtering!
It's not clear how many items Falco can support in a list - if you load 300k indicators into a list it might not work!  The best approach is to use the filtering options to formulate a highly targetted list of indicators.  This will give a much more manageable number of indicators and lower false positive rate.  I have provided a number of filtering options which are outlined in the *MISP Filtering details* details below.

There are a number of different APIs that can be used to extract the indicators out of a MISP server. There are also some complexities when filtering events server-side by date, using MISP fields like *date* or *last_seen* - not all these fields are consistent across events/objects/attributes, not all these fields are mandatory, and some fields (date) indicate the time the event occurred, not the last time an indicator was observed/changed - therefore these fields were not reliable for filtering indicators during my testing.

However, the ***timestamp*** field is mandatory for events/attributes/objects and is updated each time a change occurs.  During my testing, filtering by the ***timestamp*** field on the client-side provided much more consistent filtering, with the obvious tradeoff being that you are pulling more data from the server.

After trialling a lot of different approaches, I settled on an approach of:
- fetching the indicators using the /attributes/ API
- on client side - evaluate the timestamp field of every indicator and including it if it was newer than current time minus *misp_timeframe* days 

I am keen on feedback on this approach if there are people in the community who think there is a better approach.

## Prerequisites
The plugin requires the following items to be configured in *config.py*

**MISP Feed**
- MISP server host name - the host name of the MISP server (ex. osint.digitalside.it)
- MISP server auth key - the API auth key from the MISP Server
- MISP HTTP/HTTPS Setting - does the MISP server use HTTP or HTTPS
- MISP HTTPS Verify Cert - do you want to verify the HTTPS certificate?
- MISP Removed Deleted Indicators - do you want to remove indicators that have been soft deleted in the MISP Server?

**MISP Filtering details**
- MISP Organisation Name - retrieve indicators only from a certain organisation - '' means retrieve from all organisations
- MISP Enforce Warning List - whether to enforce the MISP Warning list - default: false
- MISP Category Filter - comma separated list of MISP categories to retrieve - '' means retrieve from all categories
- MISP Tag Filter - comma separated list of MISP tags to retrieve - '' means retrieve from all tags
- MISP Min Threat Level - minimum threat level to retrieve - use 0 to disable
- MISP Timeframe - how many days of indicators do you want to download - configure 0 to download all indicators
- MISP Event Published After - only download indicators where the event was created in the last {x} days

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
falco_malware_hash_file='/usr/share/falco/misp-file-hash.csv'

##############################################
#   Debug                                    #
##############################################
debug = False
debugindicators = False
debugyaml = False

##############################################
#   MISP Connectivity Details                #
##############################################
misp_server_url = '{YOU MISP SERVER - ex. osint.digitalside.it}'
misp_is_https = True
misp_auth_key = '{YOUR AUTH KEY}'
misp_verifycert = False
misp_remove_deleted = False

##############################################
#   MISP Filtering Details                   #
##############################################
misp_organisation_name = ''
misp_enforce_warning_list = None
misp_to_ids = None
misp_category_filter = ''
misp_tag_filter = ''
misp_min_threat_level = 0
misp_timeframe = 30                 # Fetch {x} number of days worth of indicators.  Enter 0 for ALL
misp_event_published_after = ''     # example: 5d, 30d, 12h, 30m
```

5. Execute the connector
```
./falco-misp-connector.py
```

## How can I use these lists in Falco?
You can find some sample Falco rules in the *sample-falco-rules.yaml* file in the GitHub repo - these rules will provide basic inbound/outbound detection of traffic to/from the IPs sourced from the MISP feed.

Copy *sample-falco-rules.yaml* to */etc/falco/rules.d/* directory to initiate these detections.

## Debugging
There are three configurations to help you debug the connector:
- ***debug*** - set to ***True*** for high level debug information
- ***debugindicators*** - set to ***True*** for lower level detail on each indicator
- ***debugyaml*** - set to ***True*** to debug the YAML that is outputted to each Falco list

## Issues / Feedback
- I have done quite a lot of testing, but I am only human, so there may be bugs/errors.
- Please log bugs by logging an issue on GitHub
- Please give feedback - you can do that by starting a discussion on GitHub repo!
