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
ip4_outbound_list = []
domain_list = []
sha256_dict = {}
ip6_outbound_list = []
file_list = []
uri_list = []
cidr_outbound_list = []
ip4_inbound_list = []
ip6_inbound_list = []
cidr_inbound_list = []


#################################################
# Fetch new indicators from MISP Server         #
#################################################

print("Contacting MISP Server: " + str(misp_server_url) )
ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list, cidr_outbound_list,ip4_inbound_list, ip6_inbound_list, cidr_inbound_list = fetchMISPIndicators(ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list,cidr_outbound_list, ip4_inbound_list, ip6_inbound_list,cidr_inbound_list)



#################################################
# Convert arrays to a string ready for writing  #
#################################################
# Outbound list
ip4_outbound_list_output_str =createYAMLArray(ip4_outbound_list) 
cidr_outbound_list_output_str =createYAMLArray(cidr_outbound_list) 

# Inbound list
ip4_inbound_list_output_str =createYAMLArray(ip4_inbound_list) 
cidr_inbound_list_output_str =createYAMLArray(cidr_inbound_list)

#  The IPV6 addresses need speech marks around them
# Outbound list
ip6_outbound_list_output_str =createYAMLArray(ip6_outbound_list) 
ip6_outbound_list_output_str = ip6_outbound_list_output_str.replace("[", "[\"")
ip6_outbound_list_output_str = ip6_outbound_list_output_str.replace("]", "\"]")
ip6_outbound_list_output_str = ip6_outbound_list_output_str.replace(",", "\",\"")

#Inbound List
ip6_inbound_list_output_str =createYAMLArray(ip6_inbound_list) 
ip6_inbound_list_output_str = ip6_inbound_list_output_str.replace("[", "[\"")
ip6_inbound_list_output_str = ip6_inbound_list_output_str.replace("]", "\"]")
ip6_inbound_list_output_str = ip6_inbound_list_output_str.replace(",", "\",\"")


###################################################################
# Read sample-falco-[ipv4|cidr]-rule in as a string and append it #
# This makes it easier to pass Falco validation                   #
###################################################################

# Outbound Rules
# read: sample-falco-ipv4-rule.yaml
with open("./rules/sample-falco-ipv4-outbound-rule.yaml", 'r') as file:
    ipv4_rule_content = file.read()
ip4_outbound_list_output_str = ip4_outbound_list_output_str + "\n\n" + ipv4_rule_content

# read: sample-falco-ipv6-rule.yaml
with open("./rules/sample-falco-ipv6-outbound-rule.yaml", 'r') as file:
    ipv6_rule_content = file.read()
ip6_outbound_list_output_str = ip6_outbound_list_output_str + "\n\n" + ipv6_rule_content

with open("./rules/sample-falco-cidr-outbound-rule.yaml", 'r') as file:
    cidr_rule_content = file.read()
cidr_outbound_list_output_str = cidr_outbound_list_output_str + "\n\n" + cidr_rule_content

# Inbound Rules
# read: sample-falco-ipv4-rule.yaml
with open("./rules/sample-falco-ipv4-inbound-rule.yaml", 'r') as file:
    ipv4_rule_content = file.read()
ip4_inbound_list_output_str = ip4_inbound_list_output_str + "\n\n" + ipv4_rule_content

# read: sample-falco-ipv6-rule.yaml
with open("./rules/sample-falco-ipv6-inbound-rule.yaml", 'r') as file:
    ipv6_rule_content = file.read()
ip6_inbound_list_output_str = ip6_inbound_list_output_str + "\n\n" + ipv6_rule_content

with open("./rules/sample-falco-cidr-inbound-rule.yaml", 'r') as file:
    cidr_rule_content = file.read()
cidr_inbound_list_output_str = cidr_inbound_list_output_str + "\n\n" + cidr_rule_content


###########################################################
#   Write a Newline file (used validation during testing) #
###########################################################
if 'debugtest' in globals() and debugtest == True:
    # Write IPv4 and IPv6 list 
    
    # Outbound
    print("Writing IPv4/IPv6 Outbound test valiation file")
    ip4_newline_list_output_str = createNLArray(ip4_outbound_list)
    ip6_newline_list_output_str = createNLArray(ip6_outbound_list)
    cidr_newline_list_output_str = createNLArray(cidr_outbound_list)
    ip4_ip6_cidr_newline_list_output_str = ip4_newline_list_output_str +  ip6_newline_list_output_str + cidr_newline_list_output_str
    writeNewlineFile("tests/ip46-outbound.test", ip4_ip6_cidr_newline_list_output_str )

    # Inbound
    print("Writing IPv4/IPv6 Inbound test valiation file")
    ip4_newline_list_output_str = createNLArray(ip4_inbound_list)
    ip6_newline_list_output_str = createNLArray(ip6_inbound_list)
    cidr_newline_list_output_str = createNLArray(cidr_inbound_list)
    ip4_ip6_cidr_newline_list_output_str = ip4_newline_list_output_str +  ip6_newline_list_output_str + cidr_newline_list_output_str
    writeNewlineFile("tests/ip46-inbound.test", ip4_ip6_cidr_newline_list_output_str )

    # Outbound 
    print("Writing IPv4 Rules file to test folder")
    writeFalcoRulesFileYaml("tests/ipv4-outbound-rules.yaml", falco_ipv4_outbound_list_name, ip4_outbound_list_output_str)

    print("Writing IPv6 Rules file to test folder")
    writeFalcoRulesFileYaml("tests/ipv6-outbound-rules.yaml", falco_ipv6_outbound_list_name, ip6_outbound_list_output_str)

    print("Writing CIDR Rules file to test folder")
    writeFalcoRulesFileYaml("tests/cidr-outbound-rules.yaml", falco_cidr_outbound_list_name, cidr_outbound_list_output_str)

    
    # Inbound
    print("Writing IPv4 Rules file to test folder")
    writeFalcoRulesFileYaml("tests/ipv4-inbound-rules.yaml", falco_ipv4_inbound_list_name, ip4_inbound_list_output_str)

    print("Writing IPv6 Rules file to test folder")
    writeFalcoRulesFileYaml("tests/ipv6-inbound-rules.yaml", falco_ipv6_inbound_list_name, ip6_inbound_list_output_str)

    print("Writing CIDR Rules file to test folder")
    writeFalcoRulesFileYaml("tests/cidr-inbound-rules.yaml", falco_cidr_inbound_list_name, cidr_inbound_list_output_str)

    print("Finished writing validation files - exiting")
    sys.exit(0)

#################################################################
#   Update the items in the Falco outbound rules files for IP   #
#################################################################
if debugyaml == True: print("- IPv4 Outbound YAML:" + str(ip4_outbound_list_output_str))
print("Writing out IPv4 outbound indicators to: " + falco_ipv4_outbound_rules_file)
writeFalcoRulesFileYaml(falco_ipv4_outbound_rules_file, falco_ipv4_outbound_list_name, ip4_outbound_list_output_str)

#################################################################
#   Update the items in the Falco outbound rules files for IP   #
#################################################################
if debugyaml == True: print("- IPv6 Outbound YAML:" + str(ip6_outbound_list_output_str))
print("Writing out IPv6 outbound indicators to: " + falco_ipv6_outbound_rules_file)
writeFalcoRulesFileYaml(falco_ipv6_outbound_rules_file, falco_ipv6_outbound_list_name, ip6_outbound_list_output_str)

#################################################################
#   Update the items in the Falco outbound rules files for CIDR #
#################################################################
if debugyaml == True: print("- CIDR Outbound YAML:" + str(cidr_outbound_list_output_str))
print("Writing out CIDR outbound indicators to: " + falco_cidr_outbound_rules_file)
writeFalcoRulesFileYaml(falco_cidr_outbound_rules_file, falco_cidr_outbound_list_name, cidr_outbound_list_output_str)



################################################################
#   Update the items in the Falco inbound rules files for IP   #
################################################################
if debugyaml == True: print("- IPv4 Inbound YAML:" + str(ip4_inbound_list_output_str))
print("Writing out IPv4 inbound indicators to: " + falco_ipv4_inbound_rules_file)
writeFalcoRulesFileYaml(falco_ipv4_inbound_rules_file, falco_ipv4_inbound_list_name, ip4_inbound_list_output_str)

################################################################
#   Update the items in the Falco inbound rules files for IP   #
################################################################
if debugyaml == True: print("- IPv6 Inbound YAML:" + str(ip6_inbound_list_output_str))
print("Writing out IPv6 inbound indicators to: " + falco_ipv6_inbound_rules_file)
writeFalcoRulesFileYaml(falco_ipv6_inbound_rules_file, falco_ipv6_inbound_list_name, ip6_inbound_list_output_str)

################################################################
#   Update the items in the Falco inbound rules files for CIDR #
################################################################
if debugyaml == True: print("- CIDR Inbound YAML:" + str(cidr_inbound_list_output_str))
print("Writing out CIDR inbound indicators to: " + falco_cidr_inbound_rules_file)
writeFalcoRulesFileYaml(falco_cidr_inbound_rules_file, falco_cidr_inbound_list_name, cidr_inbound_list_output_str)
