import re
from config import *
import sys

def parseConfig():
    # Check Parameters Exist
    if not 'falco_ipv4_rules_file' in globals():
        print("Configuration file parameter 'falco_ipv4_rules_file' does not seem to exist")
        sys.exit(0)
    if not 'falco_ipv4_list_name' in globals():
        print("Configuration file parameter 'falco_ipv4_list_name' does not seem to exist")
        sys.exit(0)
    if not 'falco_domain_rules_file' in globals():
        print("Configuration file parameter 'falco_domain_rules_file' does not seem to exist")
        sys.exit(0)
    if not 'falco_domain_list_name' in globals():
        print("Configuration file parameter 'falco_domain_list_name' does not seem to exist")
        sys.exit(0)
    if not 'falco_malware_hash_file' in globals():
        print("Configuration file parameter 'falco_malware_hash_file' does not seem to exist")
        sys.exit(0)
    if not 'debug' in globals():
        print("Configuration file parameter 'debug' does not seem to exist")
        sys.exit(0)
    if not 'debugindicators' in globals():
        print("Configuration file parameter 'debugindicators' does not seem to exist")
    if not 'debugyaml' in globals():
        print("Configuration file parameter 'debugyaml' does not seem to exist")
        sys.exit(0)
    if not 'misp_server_url' in globals():
        print("Configuration file parameter 'misp_server_url' does not seem to exist")
        sys.exit(0)
    if not 'misp_is_https' in globals():
        print("Configuration file parameter 'misp_is_https' does not seem to exist")
        sys.exit(0)
    if not 'misp_auth_key' in globals():
        print("Configuration file parameter 'misp_auth_key' does not seem to exist")
        sys.exit(0)
    if not 'misp_verifycert' in globals():
        print("Configuration file parameter 'misp_verifycert' does not seem to exist")
        sys.exit(0)
    if not 'misp_remove_deleted' in globals():
        print("Configuration file parameter 'misp_remove_deleted' does not seem to exist")
        
    
    
    
    # Check Parameters are valid.
    if not re.match('^(.+)\/([^\/]+)$',falco_ipv4_rules_file):
        print("Configuration file parameter 'falco_ipv4_rules_file' does not seem to be a file.  Please check parameter and try again")
        sys.exit(0)
    if not re.match('^(.+)\/([^\/]+)$', falco_domain_rules_file):
        print("Configuration file parameter 'falco_domain_rules_file' does not seem to be a file.  Please check parameter and try again")
        sys.exit(0)
    if not re.match('^(.+)\/([^\/]+)$', falco_malware_hash_file):
        print("Configuration file parameter 'falco_malware_hash_file' does not seem to be a file.  Please check parameter and try again")
        sys.exit(0)
    if not re.match('(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',misp_server_url):
        print("Configuration file parameter 'misp_server_url' does not seem to be a file.  Please check parameter and try again")
        sys.exit(0)
    if not (misp_is_https == True or misp_is_https == False):
        print("Configuration file parameter 'misp_is_https' does not seem to be True or False.  misp_is_https must equal True or False")
        sys.exit(0)
    if not (misp_verifycert == True or misp_verifycert == False):
        print("Configuration file parameter 'misp_verifycert' does not seem to be True or False.  misp_verifycert must equal True or False")
        sys.exit(0)
    if not (misp_remove_deleted == True or misp_remove_deleted == False):
        print("Configuration parameter 'misp_remove_deleted' does not seem to be true or false.  Debug must equal True or False")
        sys.exit(0)
    if not (debug == True or debug == False):
        print("Configuration file parameter 'debug' does not seem to be a file.  Debug must equal True or False")
        sys.exit(0)
    if not (debugindicators == True or debugindicators == False):
        print("Configuration file parameter 'debugindicators' does not seem to be a file.  Debug must equal True or False")
        sys.exit(0)
    if not (debugyaml == True or debugyaml == False):
        print("Configuration file parameter 'debugyaml' does not seem to be a file.  Debug must equal True or False")
        sys.exit(0)