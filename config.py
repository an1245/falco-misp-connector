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
##############################################
#   MISP Filtering Details                   #
##############################################
misp_organisation_name = ''
misp_enforce_warning_list = None
misp_to_ids = None
misp_category_filter = ''
misp_tag_filter = ''
misp_min_threat_level = 0
misp_first_seen = ''                # example: 5d, 30d, 12h, 30m
misp_last_seen = ''                 # example: 5d, 30d, 12h, 30m
misp_from = ''
misp_to = ''
misp_published_in_last = '30d'      # example: 5d, 30d, 12h, 30m -- default: last 30 days
misp_date = '30d'                   # example: 5d, 30d, 12h, 30m -- default: last 30 days
