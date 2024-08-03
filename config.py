##############################################
#   Falco configuration details              #
##############################################
# Outbound Rules
falco_ipv4_outbound_rules_file='/home/andy/rules/misp-ipv4-outbound-indicators.yaml'
falco_ipv4_outbound_list_name='malicious_ipv4_outbound_list'
falco_ipv6_outbound_rules_file='/home/andy/rules/misp-ipv6-outbound-indicators.yaml'
falco_ipv6_outbound_list_name='malicious_ipv6_outbound_list'
falco_cidr_outbound_rules_file='/home/andy/rules/misp-cidr-outbound-indicators.yaml'
falco_cidr_outbound_list_name='malicious_cidr_outbound_list'

# Inbound Rules
falco_ipv4_inbound_rules_file='/home/andy/rules/misp-ipv4-inbound-indicators.yaml'
falco_ipv4_inbound_list_name='malicious_ipv4_inbound_list'
falco_ipv6_inbound_rules_file='/home/andy/rules/misp-ipv6-inbound-indicators.yaml'
falco_ipv6_inbound_list_name='malicious_ipv6_inbound_list'
falco_cidr_inbound_rules_file='/home/andy/rules/misp-cidr-inbound-indicators.yaml'
falco_cidr_inbound_list_name='malicious_cidr_inbound_list'


##############################################
#   Debug                                    #
##############################################
debug = True
debugindicators = False
debugyaml = False

##############################################
#   MISP Connectivity Details                #
##############################################
misp_server_url = '192.168.1.68'
misp_is_https = True
misp_auth_key = 'uG3mrbfzUNoFjPeFF6TOmz38PhOwOkyV0QZ4YBPo'
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
misp_timeframe = 0                   # Fetch {x} number of days worth of indicators.  Enter 0 for ALL
misp_event_published_after = ''       # Fetch only indicators whose events were published in the last - example: 5d, 30d, 12h, 30m
misp_excludeDecayed = True
