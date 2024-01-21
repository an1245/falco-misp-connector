# MISP
from pymisp import ExpandedPyMISP
from config import *
from datetime import date
from datetime import datetime, timedelta
import dateutil.tz
import ipaddress
import json 
import urllib3
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

def fetchMISPIndicators(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list):

    #if debug == True: print("Fetching New Indicators from: "+ misp_server_url) 
    #ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = pyMISPGetNewIndicatorsByEventsAndObjects(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list)
    #if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list)
    #if debug == True: print("Finished Fetching New Indicators from: "+ misp_server_url)


    #if 'misp_remove_deleted' in globals():
    #    if (misp_remove_deleted == True):
    #        if debug == True: print("Fetching Deleted Indicators from: "+ misp_server_url) 
    #        ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = pyMISPGetDeletedIndicatorsByEventsAndObjects(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list)
    #        if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list)
    #        if debug == True: print("Finished Fetching Deleted Indicators from: "+ misp_server_url)

    # Set the timestamp we are looking at
    indicatorAfterTimestamp = 0
    if 'misp_timeframe' in globals():
        if misp_timeframe > 0:
            now = datetime.now(timezone.utc)
            indicatorAfterTimestamp = (now - timedelta(days = misp_timeframe)).strftime('%s')   


    if debug == True: print("Fetching New Indicators from Attributes for server: "+ misp_server_url + " after timestamp: " + str(indicatorAfterTimestamp)) 
    ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = pyMISPGetNewIndicatorsByAttributes(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list, indicatorAfterTimestamp)
    if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list,sha256_dict)
    if debug == True: print("Finished Fetching New Indicators from Attributes for server: "+ misp_server_url)
    
    if 'misp_remove_deleted' in globals():
        if (misp_remove_deleted == True):
            if debug == True: print("Fetching Deleted Indicators from Attributes for server: "+ misp_server_url + " after timestamp: " + str(indicatorAfterTimestamp)) 
            ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = pyMISPGetDeletedIndicatorsByAttributes(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list, indicatorAfterTimestamp)
            if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list, sha256_dict)
            if debug == True: print("Finished Fetching Deleted Indicators from Attributes for server: "+ misp_server_url)

    
    return ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list

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
        
    return body


##############################################
#  Print MISP Body Variales                      #
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
            
def pyMISPGetNewIndicatorsByAttributes(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list, indicatorAfterTimestamp):
   
    body = {
            "deleted": False,
            "type": ["filename", "sha256", "size-in-bytes", "ip-dst","domain", "hostname", "url"]
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
        misp = ExpandedPyMISP(misp_server_url_full, misp_auth_key, misp_verifycert)
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
                    if checkIPv4Address(ioc_value):
                        if debugindicators == True: print(" - Adding IPv4 Indicator: " + str(ioc_value))
                        itemAdd(ip4_list,ioc_value)
                    elif checkIPv6Address(ioc_value):
                        if debugindicators == True: print(" - Adding IPv6 Indicator: " + str(ioc_value))
                        itemAdd(ip6_list,ioc_value)
                    else: 
                        if debug == True: print(" - Unknown Indicator Value: " + str(ioc_value))
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
        

    return ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list




###########################################################################
#   Get Deleted Indicators by using MISP Attributes API                   #
#       - returns: lists with deleted indicators removed                  #
###########################################################################
            
def pyMISPGetDeletedIndicatorsByAttributes(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list, indicatorAfterTimestamp):
   
    body = {
            "deleted": True,
            "type": ["filename", "sha256", "size-in-bytes", "ip-dst","domain", "hostname", "url"]
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
        misp = ExpandedPyMISP(misp_server_url_full, misp_auth_key, misp_verifycert)
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
            match ioc_type: 
                case "sha256":
                    if ioc_value in sha256_dict.keys():
                        sha256_dict.pop(ioc_value, None)
                        if debugindicators: print("Removed Deleted hash:" + ioc_value  )  
                case "ip-dst":
                    if checkIPv4Address(ioc_value):
                        if debugindicators == True: print("Removed Deleted IPv4 Indicator: " + str(ioc_value))
                        itemRemove(ip4_list,ioc_value)
                    elif checkIPv6Address(ioc_value):
                        if debugindicators == True: print("Removed Deleted IPv6 Indicator: " + str(ioc_value))
                        itemRemove(ip6_list,ioc_value)
                    else: 
                        if debugindicators == True: print(" - Unknown Indicator Value: " + str(ioc_value))
                case "domain":
                        if debugindicators == True: print("Removed Deleted Domain Indicator: " + str(ioc_value))
                        itemRemove(domain_list,ioc_value)
                case "hostname":
                        if debugindicators == True: print("Removed Deleted Hostname Indicator: " + str(ioc_value))
                        itemRemove(domain_list,ioc_value)
                case "url":
                        if debugindicators == True: print("Removed Deleted URL Indicator: " + str(ioc_value))
                        itemRemove(uri_list,ioc_value)


    return ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list
