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

#################################################
# Check Falco list exists and read YAML from it #
#################################################
if debug == True: print("Checking for configured Falco rules files")
checkFalcoRulesFilesExists()

#################################################
# Read indicators in from Falco Files           #
#################################################

# Read IP indicator file
if debug == True: print("Reading IPv4 rules file from: " + falco_ipv4_rules_file)
falco_ipv4_yaml = returnFalcoRulesFileYaml(falco_ipv4_rules_file)
ip4_list = list(falco_ipv4_yaml[0]['items'])

if debugyaml == True: print("- IPv4 YAML:" + str(falco_ipv4_yaml))


# Read DNS indicator file
if debug == True: print("Reading DNS rules file from: " + falco_domain_rules_file)
falco_dns_yaml = returnFalcoRulesFileYaml(falco_domain_rules_file)
domain_list = list(falco_dns_yaml[0]['items'])

if debugyaml == True: print("- DNS YAML:" + str(falco_dns_yaml))

print("Reading Malware Hashes file from: " + falco_malware_hash_file)
sha256_dict = readFalcoCSVFile(falco_malware_hash_file)

# We only support IPv4 and DNS Indicators at the moment 
# But we can easily expand to support IPv6, File and URI indicators 
ip6_list = []
file_list = []
uri_list = []


#################################################
# Fetch new indicators from MISP Server         #
#################################################

print("Contacting MISP Server: " + str(misp_server_url) )
ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = fetchMISPIndicators(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list)
   

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
domain_list_output_str = createYAMLArray(domain_list)

if debugyaml == True: print("- Domain YAML:" + str(falco_dns_yaml))
print("Writing out Domain indicators to: " + falco_domain_rules_file)
writeFalcoRulesFileYaml(falco_domain_rules_file, falco_domain_list_name, domain_list_output_str)

#########################################################
#   Dump the malware file hashes to disk                #
#########################################################
print("Writing out Malware Hashes to file: " + str(falco_malware_hash_file) )
writeFalcoCSVFile(sha256_dict, falco_malware_hash_file)
