from datetime import datetime as datetime
from datetime import timezone as timezone
from datetime import timedelta as timedelta
import sys
import re
from config import *

##############################################
#  Function to check if item exists in JSON  #
#      - returns true of false               #
##############################################
def itemExists(list, item):
    
    if item in list:
        return True
    else:
        return False

##############################################
#  Function to add item to JSON              #
#      - returns list                        #
##############################################
def itemAdd(list, item):
    if item in list:
        return list
    else:
        list.append(item)
        return list

##############################################
#  Function to remove item to JSON           #
##############################################
def itemRemove(list, item):
    if item in list:
        list.remove(item)
    return list


def errorAndExit(function, responsecode, responsereason):
    print("ERROR in " + function + ": Response Code: " + str(responsecode) + " and Response Message: " + responsereason)
    sys.exit(1)

##################################################################
#  Function to find out the date at yesterday midnight           #
##################################################################

def yesterday_midnight():
    now = datetime.now(timezone.utc)
    yesterday_now = now - timedelta(1)
    yesterday_midnight = yesterday_now.strftime("%Y-%m-%dT00:00:00+00:00")
    return yesterday_midnight

##################################################################
#  Function to find out the date at last year midnight           #
##################################################################

def oneyearago_midnight():
    now = datetime.now(timezone.utc)
    yesterday_now = now - timedelta(days=365)
    yesterday_midnight = yesterday_now.strftime("%Y-%m-%dT00:00:00+00:00")
    return yesterday_midnight

def utc_time_now():
    return datetime.now(timezone.utc)


def printList(list):
    for item in list:
        print(" --- list source: " + item["source"]);
        print(" --- list name: " + item["name"]);

##############################################
#  Get value from dictionary                 #
#      - returns response                    #
##############################################
def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results

##############################################
#  Check the IP is a valid IP.               #
#      - returns true or false               #
##############################################
def checkIPv4Address(ip):
    
    if re.match('(?:[0-9]{1,3}\.){3}[0-9]{1,3}',ip):
        return True
    else:
        return False

##############################################
#  Check the IPv6 is a valid IP.               #
#      - returns true or false               #
##############################################
def checkIPv6Address(ip):
    
    if re.match('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',ip):
        return True
    else:
        return False
    
##############################################
#  Check the Domain is a valid domain        #
#      - returns true or false               #
##############################################
def checkDomainName(domain):
    
    if re.match('(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',domain):
        return True
    else:
        return False
    
##############################################
#  Print List Sizes                          #
#      - no return value                     #
##############################################
def printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list,sha256_dict):
        if debug == True: print("----------------- List Sizes -----------------")
        if debug == True: print("--             ip4_list size:" + str(len(ip4_list)))
        if debug == True: print("--             ip6_list size:" + str(len(ip6_list)))
        if debug == True: print("--             domain_list size:" + str(len(domain_list)))
        if debug == True: print("--             file_list size:" + str(len(file_list)))
        if debug == True: print("--             uri_list size:" + str(len(uri_list)))
        if debug == True: print("--             sha256_dict size:" + str(len(sha256_dict)))
        if debug == True: print("----------------------------------------------")

##############################################
#  Create YAML array to stored in Falco      #
#      - no return value                     #
##############################################
def createYAMLArray(input_list):
    input_list_output_str = "["
    for input in input_list:
        if len(input_list_output_str) == 1:
            input_list_output_str = input_list_output_str + input
        else:
            input_list_output_str = input_list_output_str + "," + input
    input_list_output_str = input_list_output_str + "]"
    return(input_list_output_str)


##############################################
#  Write the TAXII JSON to file for debug    #
#      - no return value                     #
##############################################

def outputJSONtoFile(json):
    with open('json.txt', 'a') as f:
        f.write(json)
    f.close()

##############################################
#  Identify STIX 'IN' statement and expand it#
#      - string with replaced values         #
##############################################

def expandIN(observation_expression):

    if debug == True: print(" - Expanding IN Clause: " + observation_expression)

    pattern = r'\s+(\S+)(\s+IN\s+)(\(.*?\))'
    match = re.search(pattern, observation_expression)

    object_path = match.group(1)
    object_path = object_path.lstrip()
    object_path = object_path.rstrip()


    tempIPstring = match.group(3)
    tempIPstring = tempIPstring.replace("'","")
    tempIPstring = tempIPstring.replace("(","")
    tempIPstring = tempIPstring.replace(")","")
    tempIPs = tempIPstring.split(",")

    outputstring = ""
    count = 1
    for ip in tempIPs:
        if count == 1:
            outputstring = " " + match.group(1) + " = '" + str(ip) + "'"
        else:
            outputstring = outputstring + " OR " + match.group(1) + " = '" + str(ip) + "'"
        count += 1
    
    if debug == True: print(" -- Replacing: " + match.group(0) + " with " + outputstring )
    outtext = re.sub(pattern,outputstring, observation_expression, count=1) 
    return outtext
