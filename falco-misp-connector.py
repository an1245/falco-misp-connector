#!/usr/bin/env python3

import json
import http.client
import urllib
import sys
from datetime import datetime as datetime
from datetime import timezone as timezone
from datetime import timedelta as timedelta
import time
import dateutil


##############################################
# Import the configuration parameters        #
##############################################
from config import *


##############################################
# Import MISP Functions                      #
##############################################
from misp_functions import *


##############################################
# Import utility Functions                   #
##############################################
from util_functions import *
from parse_config import *

##############################################
# Import Falco Functions                     #
##############################################
from falco_functions import *


print("Starting MISP connector")
if debug == True: print("Parsing Configuration file")
parseConfig()

# We only support IPv4 and DNS Indicators at the moment 
# But we can easily expand to support IPv6, File and URI indicators 
ip4_list = []
domain_list = []
sha256_dict = {}
ip6_list = []
file_list = []
uri_list = []


#################################################
# Fetch new indicators from MISP Server         #
#################################################

print("Contacting MISP Server: " + str(misp_server_url) )
ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = fetchMISPIndicators(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list)
   
###########################################################
#   Write a Newline file (used validation during testing) #
###########################################################
if 'debugtest' in globals() and debugtest == True:
    # Write IPv4 and IPv6 list 
    print("Writing IPv4/IPv6 test valiation file")
    ip4_newline_list_output_str = createNLArray(ip4_list)
    ip6_newline_list_output_str = createNLArray(ip6_list)
    ip4_ip6_newline_list_output_str = ip4_newline_list_output_str +  ip6_newline_list_output_str
    writeNewlineFile("tests/ip46.test", ip4_ip6_newline_list_output_str )

    # Write Domain List
    print("Writing Domain test valiation file")
    domain_list_output_str = createNLArray(domain_list)
    writeNewlineFile("tests/domain.test", domain_list_output_str)
    
    print("Finished writing validation files - exiting")
    sys.exit(0)

########################################################
#   Update the items in the Falco rules files for IP   #
########################################################
ip4_list_output_str =createYAMLArray(ip4_list) 

if debugyaml == True: print("- IPv4 YAML:" + str(falco_ipv4_yaml))
print("Writing out IP indicators to: " + falco_ipv4_rules_file)
writeFalcoRulesFileYaml(falco_ipv4_rules_file, falco_ipv4_list_name, ip4_list_output_str)


#########################################################
#   Update the items in the Falco rules files for DNS   #
#########################################################
#domain_list_output_str = createYAMLArray(domain_list)

#if debugyaml == True: print("- Domain YAML:" + str(falco_dns_yaml))
#print("Writing out Domain indicators to: " + falco_domain_rules_file)
#writeFalcoRulesFileYaml(falco_domain_rules_file, falco_domain_list_name, domain_list_output_str)

#########################################################
#   Dump the malware file hashes to disk                #
#########################################################
#print("Writing out Malware Hashes to file: " + str(falco_malware_hash_file) )
#writeFalcoCSVFile(sha256_dict, falco_malware_hash_file)
