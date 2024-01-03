# MISP
from pymisp import ExpandedPyMISP
from config import *
from datetime import date
import dateutil.tz
import ipaddress
import json 


##############################################
#   Import JSON Functions                    #
##############################################
from util_functions import *

###################################################################
#  MISP Implementation                                            #
#  Fetch all indicators from collections and return lists         #
#      - returns lists of IOCS                                    #
###################################################################

def fetchMISPIndicators(ip4_list, ip6_list, domain_list, file_list, uri_list):

    if debug == True: print("Fetching New MISP Indicators from: "+ misp_server_url)
    ip4_list, ip6_list, domain_list, file_list, uri_list = pyMISPGetNewIndicators(ip4_list, ip6_list, domain_list, file_list, uri_list)
   

    if debug == True: print("Removing Deleted MISP Indicators from: "+ misp_server_url)
    ip4_list, ip6_list, domain_list, file_list, uri_list = pyMISPRemoveDeletedIndicators(ip4_list, ip6_list, domain_list, file_list, uri_list)


    return ip4_list, ip6_list, domain_list, file_list, uri_list

##############################################
#   Collect New MISP Indicators              #
#       - returns: server connection object  #
##############################################

def pyMISPGetNewIndicators(ip4_list, ip6_list, domain_list, file_list, uri_list):
    relative_path = 'attributes/restSearch'
    body = {
        "returnFormat": "json",
        "type": ["ip-dst", "domain", "hostname", "url", "md5", "sha256"],
        "enforceWarninglist": "true",
        "to_ids": "true",
        "deleted": False,
        "last": "7d"
    }
    
    if misp_is_https == True:
            protocol = 'https'
    else:
            protocol = 'http'
        
    misp_server_url_full = protocol + '://' + misp_server_url + '/'

    misp = ExpandedPyMISP(misp_server_url_full, misp_auth_key, misp_verifycert)
    misp_response = misp.direct_call(relative_path, body)


    for attribute in misp_response['Attribute']:
        ioc_type = attribute['type']
        ioc_value = attribute['value']
        match ioc_type: 
            case "ip-dst":
                if checkIPv4Address(ioc_value):
                    if debug == True: print(" - Adding IPv4 Indicator: " + str(ioc_value))
                    itemAdd(ip4_list,ioc_value)
                elif checkIPv6Address(ioc_value):
                    if debug == True: print(" - Adding IPv6 Indicator: " + str(ioc_value))
                    itemAdd(ip6_list,ioc_value)
                else: 
                    if debug == True: print(" - Unknown Indicator Value: " + str(ioc_value))
            case "domain":
                if checkDomainName(ioc_value):
                    if debug == True: print(" - Adding Domain Indicator: " + str(ioc_value))
                    itemAdd(domain_list,ioc_value)
            case "hostname":
                if checkDomainName(ioc_value):
                    if debug == True: print(" - Adding Hostname Indicator: " + str(ioc_value))
                    itemAdd(domain_list,ioc_value)
            case "url":
                    if debug == True: print(" - Adding URL Indicator: " + str(ioc_value))
                    itemAdd(uri_list,ioc_value)
            case "md5":
                    if debug == True: print(" - Adding MD5 Indicator: " + str(ioc_value))
                    itemAdd(file_list,ioc_value)
            case "sha256":
                    if debug == True: print(" - Adding SHA256 Indicator: " + str(ioc_value))
                    itemAdd(file_list,ioc_value)
        

    return ip4_list, ip6_list, domain_list, file_list, uri_list

##############################################
#   Collect Remove MISP Indicators           #
#       - returns: server connection object  #
##############################################

def pyMISPRemoveDeletedIndicators(ip4_list, ip6_list, domain_list, file_list, uri_list):
    relative_path = '/attributes/restSearch'
    body = {
        "returnFormat": "json",
        "type": ["ip-dst", "domain", "hostname", "url", "md5", "sha256"],
        "enforceWarninglist": "true",
        "to_ids": "true",
        "deleted": True,
        "last": "7d"
    }
    
    if misp_is_https == True:
            protocol = 'https'
    else:
            protocol = 'http'
        
    misp_server_url_full = protocol + '://' + misp_server_url + '/'
    
    misp = ExpandedPyMISP(misp_server_url_full, misp_auth_key, misp_verifycert)
    misp_response = misp.direct_call(relative_path, body)

    for attribute in misp_response['Attribute']:
       ioc_type = attribute['type']
       ioc_value = attribute['value']
       match ioc_type: 
            case "ip-dst":
                if checkIPv4Address(ioc_value):
                    if debug == True: print(" - Removing IPv4 Indicator: " + str(ioc_value))
                    itemRemove(ip4_list,ioc_value)
                elif checkIPv6Address(ioc_value):
                    if debug == True: print(" - Removing IPv6 Indicator: " + str(ioc_value))
                    itemRemove(ip6_list,ioc_value)
                else: 
                    if debug == True: print(" - Unknown Indicator Value: " + str(ioc_value))
            case "domain":
                    if debug == True: print(" - Removing Domain Indicator: " + str(ioc_value))
                    itemRemove(domain_list,ioc_value)
            case "hostname":
                    if debug == True: print(" - Removing Hostname Indicator: " + str(ioc_value))
                    itemRemove(domain_list,ioc_value)
            case "url":
                    if debug == True: print(" - Removing URL Indicator: " + str(ioc_value))
                    itemRemove(uri_list,ioc_value)
            case "md5":
                    if debug == True: print(" - Removing MD5 Indicator: " + str(ioc_value))
                    itemRemove(file_list,ioc_value)
            case "sha256":
                    if debug == True: print(" - Removing SHA256 Indicator: " + str(ioc_value))
                    itemRemove(file_list,ioc_value)

    return ip4_list, ip6_list, domain_list, file_list, uri_list