# Falco MISP Connector

## Introduction
The Falco MISP Connector sources indicators from MISP server and consolidates them into a Falco list.  Currently the connector brings in *ip-src* and *ip-dst* indictors from a MISP server, breaking them out into a separate rule file for inbound (*ip-src*) IPv4, IPv6 and CIDR block, and outbound (*ip-dst*)  IPv4, IPv6 and CIDR block.

## Note Before - Indicator Filtering!
It's not clear how many items Falco can support in a list - if you load 300k indicators into a list it might not work!  The best approach is to use the filtering options to formulate a highly targetted list of indicators.  This will give a much more manageable number of indicators and lower false positive rate.  I have provided a number of filtering options which are outlined in the *MISP Filtering details* details below.

There are a number of different APIs that can be used to extract the indicators out of a MISP server. There are also some complexities when filtering events server-side by date, using MISP fields like *date* or *last_seen* - not all these fields are consistent across events/objects/attributes, not all these fields are mandatory, and some fields (date) indicate the time the event occurred, not the last time an indicator was observed/changed - therefore these fields were not reliable for filtering indicators during my testing.

However, the ***timestamp*** field is mandatory for events/attributes/objects and is updated each time a change occurs.  During my testing, filtering by the ***timestamp*** field on the client-side provided much more consistent filtering, with the obvious tradeoff being that you are pulling more data from the server.

After trialling a lot of different approaches, I settled on an approach of:
- fetching the indicators using the /attributes/ API
- on client side - evaluate the timestamp field of every indicator and including it if it was newer than current time minus *misp_timeframe* days 

## Prerequisites
The plugin requires the inbound macro which is currently in the Falco sandbox rules.

The plugin requires the following items to be configured in *config.py*

**MISP Feed**
- MISP server host name - the host name of the MISP server (ex. osint.digitalside.it)
- MISP server auth key - the API auth key from the MISP Server
- MISP HTTP/HTTPS Setting - does the MISP server use HTTP or HTTPS
- MISP HTTPS Verify Cert - do you want to verify the HTTPS certificate?

**MISP Filtering details**
- MISP Organisation Name - retrieve indicators only from a certain organisation - '' means retrieve from all organisations
- MISP Enforce Warning List - whether to enforce the MISP Warning list - default: false
- MISP Category Filter - comma separated list of MISP categories to retrieve - '' means retrieve from all categories
- MISP Tag Filter - comma separated list of MISP tags to retrieve - '' means retrieve from all tags
- MISP Min Threat Level - minimum threat level to retrieve - use 0 to disable
- MISP Timeframe - how many days of indicators do you want to download - configure 0 to download all indicators
- MISP Event Published After - only download indicators where the event was created in the last {x} days
- MISP Exclude Decayed - Filter out all expired IOCs according to the Decay Model you have selected.

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
# Outbound Rules
falco_ipv4_outbound_rules_file='/etc/falco/rules.d/misp-ipv4-outbound-indicators.yaml'
falco_ipv4_outbound_list_name='malicious_ipv4_outbound_list'
falco_ipv6_outbound_rules_file='/etc/falco/rules.d/misp-ipv6-outbound-indicators.yaml'
falco_ipv6_outbound_list_name='malicious_ipv6_outbound_list'
falco_cidr_outbound_rules_file='/etc/falco/rules.d/misp-cidr-outbound-indicators.yaml'
falco_cidr_outbound_list_name='malicious_cidr_outbound_list'

# Inbound Rules
falco_ipv4_inbound_rules_file='/etc/falco/rules.d/misp-ipv4-inbound-indicators.yaml'
falco_ipv4_inbound_list_name='malicious_ipv4_inbound_list'
falco_ipv6_inbound_rules_file='/etc/falco/rules.d/misp-ipv6-inbound-indicators.yaml'
falco_ipv6_inbound_list_name='malicious_ipv6_inbound_list'
falco_cidr_inbound_rules_file='/etc/falco/rules.d/misp-cidr-inbound-indicators.yaml'
falco_cidr_inbound_list_name='malicious_cidr_inbound_list'

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

##############################################
#   MISP Filtering Details                   #
##############################################
misp_organisation_name = ''
misp_enforce_warning_list = None
misp_to_ids = True
misp_category_filter = ''
misp_tag_filter = ''
misp_min_threat_level = 0
misp_timeframe = 0                 # Fetch {x} number of days worth of indicators.  Enter 0 for ALL
misp_event_published_after = ''     # example: 5d, 30d, 12h, 30m
misp_excludeDecayed = True        
```

5. Execute the connector
```
./falco-misp-connector.py
```

## How can I use these lists in Falco?
The script will automatically append the six sample rules files in the rules directory (sample-falco-cidr-rule.yaml, sample-falco-ipv4-rule.yaml and sample-falco-ipv6-rule.yaml) to the end of the three Falco rules files that the connector generates - in these sample rules file you will find lists to create exceptions.  The three rules files that the connector generates (IPv4,IPv6 and CIDR) can then be copied into /etc/falco/rules.d/ directory and Falco restarted. 

## Debugging
There are three configurations to help you debug the connector:
- ***debug*** - set to ***True*** for high level debug information
- ***debugindicators*** - set to ***True*** for lower level detail on each indicator
- ***debugyaml*** - set to ***True*** to debug the YAML that is outputted to each Falco list

## Issues / Feedback
- I have done quite a lot of testing, but I am only human, so there may be bugs/errors.
- Please log bugs by logging an issue on GitHub
- Please give feedback - you can do that by starting a discussion on GitHub repo!
