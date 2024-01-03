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