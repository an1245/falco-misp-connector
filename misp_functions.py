# MISP
from pymisp import ExpandedPyMISP
from config import *
from datetime import date
from datetime import datetime
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

    if debug == True: print("Fetching New Indicators from: "+ misp_server_url) 
    ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = pyMISPGetNewIndicators2(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list)
    if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list)
    if debug == True: print("Finished Fetching New Indicators from: "+ misp_server_url)


    if debug == True: print("Fetching Deleted Indicators from: "+ misp_server_url) 
    ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = pyMISPRemoveNewIndicators2(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list)
    if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list)
    if debug == True: print("Finished Fetching Deleted Indicators from: "+ misp_server_url)


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

    if 'misp_first_seen' in globals():
        if len(misp_first_seen) > 0:
            body["first_seen"] = misp_first_seen

    if 'misp_last_seen' in globals():
        if len(misp_last_seen) > 0:
            body["last_seen"] = misp_last_seen

    if 'misp_published_in_last' in globals():
        if len(misp_published_in_last) > 0:
            body["last"] = misp_published_in_last

    if 'misp_date' in globals():
        if len(misp_date) > 0:
            body["date"] = misp_date

    if 'misp_from' in globals():
        if len(misp_from) > 0:
            body["from"] = misp_from
    
    if 'misp_to' in globals():
        if len(misp_to) > 0:
            body["to"] = misp_to
        
            
    
    return body


##############################################
#   New Collect File Hash Indicators         #
#       - returns: server connection object  #
##############################################

def pyMISPGetNewIndicators2(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list):
   
    body = {
            "deleted": False,
    }
 

    body = pyMISPBuildHTTPBody(body)
   
    if debug == True:
        printMISPBody(body)

    #########################################
    # Grab the indicators out of the events #
    ######################################### 
    relative_path = 'events/restSearch'
    
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

 
    for event in misp_response:
        sha256_value = ""
        filename_value = ""
        size_value = 0
        ipdst_value = ""
        for key, value in event['Event'].items():
            if key == "id":
                 if debugindicators: print("- Processing Event ID:" + value)
            if key =="timestamp":
                 timestamp_value = datetime.fromtimestamp(int(value))

            if key =="Attribute":
                for attribute in value:
                    ioc_type = attribute['type']
                    ioc_value = attribute['value']
                    match ioc_type: 
                        case "sha256":
                            if debugindicators: print("-- Processing SHA256:" + ioc_value)
                            sha256_value = ioc_value
                        case "filename":
                            if debugindicators: print("-- Processing SHA256: " + sha256_value + " Filename :" + ioc_value)
                            filename_value = ioc_value
                        case "size-in-bytes":
                            if debugindicators: print("-- Processing SHA256: " + sha256_value + " File Size:" + ioc_value)
                            size_value = ioc_value
                        case "ip-dst":
                            if checkIPv4Address(ioc_value):
                                if debugindicators: print("-- Processing IP-DST: " + ioc_value )
                                itemAdd(ip4_list,ioc_value)
                            elif checkIPv6Address(ioc_value):
                                if debugindicators: print("-- Processing IP-DST: " + ioc_value )
                                itemAdd(ip6_list,ioc_value)
                            else: 
                                if debug == True: print(" - Unknown Indicator Value: " + str(ioc_value))
                        case "url":
                            if debugindicators: print("-- Processing URL: " + ioc_value )
                            itemAdd(uri_list, ioc_value)
                        case "domain":
                            if checkDomainName(ioc_value):
                                if debugindicators: print("-- Processing Domain: " + ioc_value )
                                itemAdd(domain_list, ioc_value)
                        case "hostname":
                            if checkDomainName(ioc_value):
                                if debugindicators: print("-- Processing Hostname: " + ioc_value )
                                itemAdd(domain_list, ioc_value)
                        case _:
                            if debugindicators: print("-- Identified Unknown Value:" + ioc_type)  


        if len(sha256_value) > 0:
            sha256_dict[sha256_value] = [str(filename_value) ,str(size_value), str(timestamp_value)]
            if debugindicators: print("Storing hash:" + sha256_value + "   = ['" + sha256_dict[sha256_value][0] + "','" + sha256_dict[sha256_value][1] + "','" + sha256_dict[sha256_value][2] + "']")



    ##########################################
    # Grab the indicators out of the objects #
    ########################################## 
    relative_path = 'objects/restSearch'

    try:
        misp = ExpandedPyMISP(misp_server_url_full, misp_auth_key, misp_verifycert)
        misp_response = misp.direct_call(relative_path, body)
    except Exception as err:
        print(f"Can't contact MISP Server - check your URL and auth key {err=}, {type(err)=}")
        raise

    for object in misp_response:
        sha256_value = ""
        filename_value = ""
        size_value = 0
        for key, value in object['Object'].items():
            if key == "id":
                 if debugindicators: print("- Processing Object ID:" + value)
            if key =="timestamp":
                 timestamp_value = datetime.fromtimestamp(int(value))

            if key =="Attribute":
                for attribute in value:
                    ioc_type = attribute['type']
                    ioc_value = attribute['value']
                    match ioc_type: 
                        case "sha256":
                            if debugindicators: print("-- Processing SHA256:" + ioc_value)
                            sha256_value = ioc_value
                        case "filename":
                            if debugindicators: print("-- Processing SHA256: " + sha256_value + " Filename :" + ioc_value)
                            filename_value = ioc_value
                        case "size-in-bytes":
                            if debugindicators: print("-- Processing SHA256: " + sha256_value + " File Size:" + ioc_value)
                            size_value = ioc_value
                        case "ip-dst":
                            if checkIPv4Address(ioc_value):
                                if debugindicators: print("-- Processing IP-DST: " + ioc_value )
                                itemAdd(ip4_list,ioc_value)
                            elif checkIPv6Address(ioc_value):
                                if debugindicators: print("-- Processing IP-DST: " + ioc_value )
                                itemAdd(ip6_list,ioc_value)
                            else: 
                                if debug == True: print(" - Unknown Indicator Value: " + str(ioc_value))
                        case "url":
                            if debugindicators: print("-- Processing URL: " + ioc_value )
                            itemAdd(uri_list, ioc_value)
                        case "domain":
                            if checkDomainName(ioc_value):
                                if debugindicators: print("-- Processing Domain: " + ioc_value )
                                itemAdd(domain_list, ioc_value)
                        case "hostname":
                            if checkDomainName(ioc_value):
                                if debugindicators: print("-- Processing Hostname: " + ioc_value )
                                itemAdd(domain_list, ioc_value)
                        case _:
                            if debugindicators: print("-- Identified Unknown Value:" + ioc_type)   


        if len(sha256_value) > 0:
            sha256_dict[sha256_value] = [str(filename_value) ,str(size_value), str(timestamp_value)]
            if debugindicators: print("Storing hash:" + sha256_value + "   = ['" + sha256_dict[sha256_value][0] + "','" + sha256_dict[sha256_value][1] + "','" + sha256_dict[sha256_value][2] + "']")


    return  ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list


##############################################
#   New Remove Indicators              #
#       - returns: server connection object  #
##############################################

def pyMISPRemoveNewIndicators2(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list):
   
    body = {
            "deleted": True,
    }
 

    body = pyMISPBuildHTTPBody(body)
   
    if debug == True:
        printMISPBody(body)

    #########################################
    # Grab the indicators out of the events #
    ######################################### 
    relative_path = 'events/restSearch'
    
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

 
    for event in misp_response:
        sha256_value = ""
        filename_value = ""
        size_value = 0
        for key, value in event['Event'].items():
            if key == "id":
                 if debugindicators: print("- Processing Remove Event ID:" + value)

            if key =="timestamp":
                 timestamp_value = datetime.fromtimestamp(int(value))

            if key =="Attribute":
                for attribute in value:
                    ioc_type = attribute['type']
                    ioc_value = attribute['value']
                    match ioc_type: 
                        case "sha256":
                            if debugindicators: print("-- Processing SHA256:" + ioc_value)
                            sha256_value = ioc_value
                        case "filename":
                            filename_value = ioc_value
                        case "size-in-bytes":
                            size_value = ioc_value
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

        if len(sha256_value) > 0:
            if sha256_value in sha256_dict.keys():
                sha256_dict.pop(sha256_value, None)
                if debugindicators: print("Removed Deleted hash:" + sha256_value  )

        

    ##########################################
    # Grab the indicators out of the objects #
    ########################################## 
    relative_path = 'objects/restSearch'

    try:
        misp = ExpandedPyMISP(misp_server_url_full, misp_auth_key, misp_verifycert)
        misp_response = misp.direct_call(relative_path, body)
    except Exception as err:
        print(f"Can't contact MISP Server - check your URL and auth key {err=}, {type(err)=}")
        raise

    for object in misp_response:
        sha256_value = ""
        filename_value = ""
        size_value = 0
        for key, value in object['Object'].items():
            if key == "id":
                 if debugindicators: print("- Processing Remove Object ID:" + value)
            if key =="timestamp":
                 timestamp_value = datetime.fromtimestamp(int(value))

            if key =="Attribute":
                for attribute in value:
                    ioc_type = attribute['type']
                    ioc_value = attribute['value']
                    match ioc_type: 
                        case "sha256":
                            if debugindicators: print("-- Removing SHA256:" + ioc_value)
                            sha256_value = ioc_value
                        case "filename":
                            filename_value = ioc_value
                        case "size-in-bytes":
                            size_value = ioc_value
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
                        case _:
                            if debugindicators: print("-- Identified Unknown Value:" + ioc_type)  


        if len(sha256_value) > 0:
            sha256_dict.pop(sha256_value, None)
            if debugindicators: print("Removed Deleted hash:" + sha256_value  )

        
    return  ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list


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

