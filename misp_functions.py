# MISP
from pymisp import PyMISP
from config import *
from datetime import date
from datetime import datetime, timedelta
import dateutil.tz
import ipaddress
import json 
import urllib3
import ipaddress
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


##############################################
#   Import JSON Functions                    #
##############################################
from util_functions import *

###################################################################
#  MISP Implementation                                            #
#  Fetch all indicators from collections and return lists         #
#      - returns lists of IOCS                                    #
###################################################################

def fetchMISPIndicators(ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list,cidr_outbound_list,ip4_inbound_list, ip6_inbound_list,cidr_inbound_list, ipdstport_list, ipsrcport_list):

    # Set the timestamp we are looking at
    indicatorAfterTimestamp = 0
    if 'misp_timeframe' in globals():
        if misp_timeframe > 0:
            now = datetime.now(timezone.utc)
            indicatorAfterTimestamp = (now - timedelta(days = misp_timeframe)).strftime('%s')   


    print("Fetching New Indicators from Attributes for server: "+ misp_server_url + " after timestamp: " + str(indicatorAfterTimestamp)) 
    ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list, cidr_outbound_list, ip4_inbound_list, ip6_inbound_list,cidr_inbound_list, ipdstport_list, ipsrcport_list = pyMISPGetNewIndicatorsByAttributes(ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list, cidr_outbound_list, ip4_inbound_list, ip6_inbound_list,cidr_inbound_list, ipdstport_list, ipsrcport_list, indicatorAfterTimestamp)    
    if debug == True: printListSizes(ip4_outbound_list, ip6_outbound_list, domain_list, file_list, uri_list,cidr_outbound_list, sha256_dict,ip4_inbound_list, ip6_inbound_list,cidr_inbound_list)
    if debug == True: print("Finished Fetching New Indicators from Attributes for server: "+ misp_server_url)
    
    
    return ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list, cidr_outbound_list, ip4_inbound_list, ip6_inbound_list, cidr_inbound_list, ipdstport_list, ipsrcport_list

##############################################
#   Build HTTP Body                          #
#       - returns: server connection object  #
##############################################
def pyMISPBuildHTTPBody(body):

    body["returnFormat"] =  "json"

    if 'misp_organisation_name' in globals():
        if len(misp_organisation_name) > 0:
            body["org"] = misp_organisation_name
    
    if 'misp_enforce_warning_list' in globals():
            if (misp_enforce_warning_list == True or misp_enforce_warning_list == False):
                body["enforceWarninglist"] = misp_enforce_warning_list
    
    if 'misp_to_ids' in globals():
            if (misp_to_ids == True or misp_to_ids == False):
                body["to_ids"] = misp_to_ids
       
    if 'misp_category_filter' in globals():
        if len(misp_category_filter) > 0:
            body["category"] = misp_category_filter
    
    if 'misp_tag_filter' in globals():
        if len(misp_tag_filter) > 0:
            body["tags"] = [misp_tag_filter]
    
    if 'misp_min_threat_level' in globals():
        if type(misp_min_threat_level) is int and misp_min_threat_level > 0 and misp_min_threat_level < 4:
            body["threat_level_id"] = misp_min_threat_level
    
    if 'misp_event_published_after' in globals():
        if len(misp_event_published_after) > 0:
            body["last"] = misp_event_published_after

    if 'misp_excludeDecayed' in globals():
            if (misp_excludeDecayed == True or misp_excludeDecayed == False):
                body["excludeDecayed"] = misp_excludeDecayed
        
    return body


##############################################
#  Print MISP Body Variales                  #
#      - no return value                     #
##############################################
def printMISPBody(body):
        if debug == True: 
            print("----------------- MISP Body Variables -----------------")
            for k,v in body.items():
                print("--             " + str(k) + "=" + str(v))
            print("-------------------------------------------------------")



###########################################################################
#   Get New Indicators by using MISP Attributes API                       #
#       - returns: lists with new indicators added                        #
###########################################################################
            
def pyMISPGetNewIndicatorsByAttributes(ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list, cidr_outbound_list, ip4_inbound_list, ip6_inbound_list,cidr_inbound_list, ipdstport_list, ipsrcport_list, indicatorAfterTimestamp):
   
    body = {
            "deleted": False,
            #"type": ["filename", "sha256", "size-in-bytes", "ip-dst","domain", "hostname", "url"]
            "type": ["ip-dst","ip-src","ip-dst|port","ip-src|port"]
    }

    body = pyMISPBuildHTTPBody(body)
   
    if debug == True:
        printMISPBody(body)

    relative_path = 'attributes/restSearch'
    
    if misp_is_https == True:
            protocol = 'https'
    else:
            protocol = 'http'
        
    misp_server_url_full = protocol + '://' + misp_server_url + '/'

    try:
        misp = PyMISP(misp_server_url_full, misp_auth_key, misp_verifycert)
        misp_response = misp.direct_call(relative_path, body)
    except Exception as err:
        print(f"Can't contact MISP Server - check your URL and auth key {err=}, {type(err)=}")
        raise

    eventDict = {}

    for attribute in misp_response['Attribute']:
        
        # Check the indicator is within the timeframe
        if int(attribute["timestamp"]) > int(indicatorAfterTimestamp):
            ioc_type = attribute['type']
            ioc_value = attribute['value']
            ioc_event_id = attribute['event_id']
            ioc_object_id = attribute['object_id']
            eventDictId = str(ioc_event_id) + "-" + str(ioc_object_id)
            if not eventDictId in eventDict:
                eventDict[eventDictId] = {"sha256":"", "filename":"", "size-in-bytes":"", "timestamp":""}
            
            match ioc_type: 
                case "sha256":
                    if debugindicators: print("-- Processing SHA256:" + ioc_value)
                    eventDict[eventDictId]["sha256"] = ioc_value
                case "filename":
                    if debugindicators: print("-- Processing Filename Value: " + ioc_value)
                    eventDict[eventDictId]["filename"] = ioc_value
                case "size-in-bytes":
                    if debugindicators: print("-- Processing File Size Value: " + ioc_value)
                    eventDict[eventDictId]["size-in-bytes"] = ioc_value
                case "timestamp":
                    if debugindicators: print("-- Processing Timestamp Value: " + ioc_value)
                    eventDict[eventDictId]["timestamp"] = ioc_value 
                case "ip-dst":
                    ip4_outbound_list, ip6_outbound_list, cidr_outbound_list = checkIP(ioc_value, ip4_outbound_list, ip6_outbound_list, cidr_outbound_list)
                case "ip-src":
                    ip4_inbound_list, ip6_inbound_list, cidr_inbound_list = checkIP(ioc_value, ip4_inbound_list, ip6_inbound_list, cidr_inbound_list)
                case "ip-dst|port":
                    if debugindicators == True: print(" - Adding ip-dst|port Indicator: " + str(ioc_value))
                    itemAdd(ipdstport_list,ioc_value)
                case "ip-src|port":
                    if debugindicators == True: print(" - Adding ip-src|port Indicator: " + str(ioc_value))
                    itemAdd(ipsrcport_list,ioc_value)
                case "domain":
                    if checkDomainName(ioc_value):
                        if debugindicators == True: print(" - Adding Domain Indicator: " + str(ioc_value))
                        itemAdd(domain_list,ioc_value)
                case "hostname":
                    if checkDomainName(ioc_value):
                        if debugindicators == True: print(" - Adding Hostname Indicator: " + str(ioc_value))
                        itemAdd(domain_list,ioc_value)
                case "url":
                        if debugindicators == True: print(" - Adding URL Indicator: " + str(ioc_value))
                        itemAdd(uri_list,ioc_value)
                case _:
                        if debugindicators: print("-- Identified Unknown Value:" + ioc_type)
        
    # Circle through the eventDict and compile the Hash Values
    
    for k,v in eventDict.items():
        sha256_value = v["sha256"]
        filename_value = v["filename"]
        size_value = v["size-in-bytes"]
        timestamp_value = v["timestamp"]

        if len(sha256_value) > 0:
            sha256_dict[sha256_value] = [str(filename_value) ,str(size_value), str(timestamp_value)]
            if debugindicators: print("Storing hash:" + sha256_value + "   = ['" + sha256_dict[sha256_value][0] + "','" + sha256_dict[sha256_value][1] + "','" + sha256_dict[sha256_value][2] + "']")
        

    return ip4_outbound_list, ip6_outbound_list, domain_list, file_list, sha256_dict, uri_list, cidr_outbound_list, ip4_inbound_list, ip6_inbound_list, cidr_inbound_list, ipdstport_list, ipsrcport_list
    
###########################################################################
#   Checks whether the MISP entry is an IPv4, IPv6 or a CIDR Block        #
#       - returns: lists with new indicators added                        #
###########################################################################


def checkIP(ip,ip4_list, ip6_list,cidr_list):
    is_cidr=False

    # Are we dealing with an IPv4 or IPv6 address?
    ipv6=False
    if ":" in ip: ipv6=True
    try:
        if debugindicators: print("Working with IP: " + ip + " - ", end="")

        # Look for a slash (/) in the address
        if "/" in ip:
            if debugindicators: print("this is a CIDR block - ",end="")

            # This is a CIDR block
            iscidr=True

            # Create an ipaddress object
            ipobject = ipaddress.ip_network(ip)


            # If this is a /32 (IPv4) or /128 (IPv6) prefix length then it's a host address
            if (ipv6 == False and ipobject.prefixlen == 32) or (ipv6 == True and ipobject.prefixlen == 128):
                ipstr = ip.split("/")[0]
                if ipv6 == False:
                    if checkIPv4Address(ipstr):
                        if debugindicators == True: print("an IPv4 /32 mask - ",end="")
                        if debugindicators == True: print("adding to ip4_list",end="")
                        itemAdd(ip4_list, ipstr)
                    else:
                        print("Failed to validate IPv4 Indicator(1): " + str(ipstr),end="")
                else:
                    if checkIPv6Address(ipstr):
                        if debugindicators == True: print("an IPv6 /128 mask - ",end="")
                        if debugindicators == True: print("adding to ip6_list ",end="")
                        itemAdd(ip6_list,ipstr)
                    else:
                        if debugindicators == True: print("failed to validate indicator(1)",end="")
            # Otherwise it is a CIDR address
            else:
                itemAdd(cidr_list, ip )
                if debugindicators == True: print("it is valid - ",end="")
                if debugindicators == True: print("adding to cidr_list ",end="")

        # If there isn't a / then we are dealing with an IP address
        else:
            if debugindicators: print("this is an IP Address - ",end="")
            ipaddress.ip_address(ip)
            if ipv6==True:
                if checkIPv6Address(ip):
                        if debugindicators == True: print("an IPv6 Address - ",end="")
                        if debugindicators == True: print("adding to ip6_list",end="")
                        itemAdd(ip6_list,ip)
                else:
                        if debugindicators == True: print("failed to validate IPv6 Indicator(2)",end="")
            else:
                   if checkIPv4Address(ip):
                        if debugindicators == True: print("an IPv4 address - ",end="")
                        if debugindicators == True: print("adding to ip4_list",end="")
                        itemAdd(ip4_list, ip)
                   else:
                        if debugindicators == True: print("failed to validate IPv4 Indicator(2)",end="")

    # If there is any error in that is triggered then it's invalid.
    except ValueError:
        if is_cidr:
            print("it's actually an invalid CIDR - skipping",end="")
        else:
            print("it's actually an invalid IP - skipping",end="")
    if debugindicators: print("")

    return ip4_list, ip6_list,cidr_list
