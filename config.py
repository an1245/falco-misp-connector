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
falco_ipdstport_outbound_rules_file='/etc/falco/rules.d/misp-ipdstport-outbound-indicators.yaml'
falco_ipdstport_outbound_list_name = 'malicious_ipdstport_outbound_list'

# Inbound Rules
falco_ipv4_inbound_rules_file='/etc/falco/rules.d/misp-ipv4-inbound-indicators.yaml'
falco_ipv4_inbound_list_name='malicious_ipv4_inbound_list'
falco_ipv6_inbound_rules_file='/etc/falco/rules.d/misp-ipv6-inbound-indicators.yaml'
falco_ipv6_inbound_list_name='malicious_ipv6_inbound_list'
falco_cidr_inbound_rules_file='/etc/falco/rules.d/misp-cidr-inbound-indicators.yaml'
falco_cidr_inbound_list_name='malicious_cidr_inbound_list'
falco_ipsrcport_inbound_rules_file='/etc/falco/rules.d/misp-ipsrcport-inbound-indicators.yaml'
falco_ipsrcport_inbound_list_name = 'malicious_ipsrcport_inbound_list'

##############################################
#   Debug                                    #
##############################################
debug = True
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
misp_timeframe = 0                    # Fetch {x} number of days worth of indicators.  Enter 0 for ALL
misp_event_published_after = ''       # Fetch only indicators whose events were published in the last - example: 5d, 30d, 12h, 30m
misp_excludeDecayed = True
