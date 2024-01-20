def fetchMISPIndicators(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list):

    #if debug == True: print("Fetching New MISP Indicators from: "+ misp_server_url)
    #ip4_list, ip6_list, domain_list, uri_list = pyMISPGetNewIndicators(ip4_list, ip6_list, domain_list,  uri_list)
    #if debug == True: print("Finished fetching new MISP Indicators from: "+ misp_server_url)
    #if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list)

    #if debug == True: print("Removing Deleted MISP Indicators from: "+ misp_server_url)
    #ip4_list, ip6_list, domain_list,  uri_list = pyMISPRemoveDeletedIndicators(ip4_list, ip6_list, domain_list,  uri_list)
    #if debug == True: print("Finished removing Deleted MISP Indicators from: "+ misp_server_url)
    #if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list)

    #if debug == True: print("Fetching New Malware Hash Indicators from: "+ misp_server_url) 
    #sha256_dict = pyMISPGetNewFileHashIndicators(sha256_dict)
    #if debug == True: print("Finished fetching Malware Hash Indicators from: "+ misp_server_url)

    ##if debug == True: print("Removing Deleted Malware Hash Indicators from: "+ misp_server_url) 
    ##sha256_dict = pyMISPRemoveFileHashIndicators(sha256_dict)
    ##if debug == True: print("Finished fetching Malware Hash Indicators from: "+ misp_server_url)


    if debug == True: print("Fetching New Indicators from: "+ misp_server_url) 
    ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list = pyMISPGetNewIndicators2(ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list)
    if debug == True: printListSizes(ip4_list, ip6_list, domain_list, file_list, uri_list)
    if debug == True: print("Finished fetching NewIndicators from: "+ misp_server_url)



    return ip4_list, ip6_list, domain_list, file_list, sha256_dict, uri_list

##############################################
#   Legacy Collect New MISP Indicators       #
#       - returns: server connection object  #
##############################################

def pyMISPGetIndicatorsByAttributes(ip4_list, ip6_list, domain_list, uri_list):
   
    body = {
            "deleted": False,
            "type": ["ip-dst", "domain", "hostname", "url"]
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


    for attribute in misp_response['Attribute']:
        ioc_type = attribute['type']
        ioc_value = attribute['value']
        match ioc_type: 
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

        

    return ip4_list, ip6_list, domain_list,  uri_list

##############################################
#   Collect Remove MISP Indicators           #
#       - returns: server connection object  #
##############################################

def pyMISPGetDeletedIndicatorsByAttributes(ip4_list, ip6_list, domain_list, uri_list):
    relative_path = '/attributes/restSearch'

    body = {
            "deleted": True,
            "type": ["ip-dst", "domain", "hostname", "url"]
    }
 
    body = pyMISPBuildHTTPBody(body)

    if debug == True:
        printMISPBody(body)
    
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


    return ip4_list, ip6_list, domain_list, uri_list


##############################################
#   Collect File Hash Indicators         #
#       - returns: server connection object  #
##############################################

def pyMISPGetNewFileHashIndicators(shd256_dict):
   
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
                        case _:
                            if debugindicators: print("-- Identified Unknown Value:" + ioc_type)  


        if len(sha256_value) > 0:
            shd256_dict[sha256_value] = [str(filename_value) ,str(size_value), str(timestamp_value)]
            if debugindicators: print("Storing hash:" + sha256_value + "   = ['" + shd256_dict[sha256_value][0] + "','" + shd256_dict[sha256_value][1] + "','" + shd256_dict[sha256_value][2] + "']")


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
                        case _:
                            if debugindicators: print("-- Identified Unknown Value:" + ioc_type)   


        if len(sha256_value) > 0:
            shd256_dict[sha256_value] = [str(filename_value) ,str(size_value), str(timestamp_value)]
            if debugindicators: print("Storing hash:" + sha256_value + "   = ['" + shd256_dict[sha256_value][0] + "','" + shd256_dict[sha256_value][1] + "','" + shd256_dict[sha256_value][2] + "']")


    return  shd256_dict


##############################################
#   Remove File Hash Indicators              #
#       - returns: server connection object  #
##############################################

def pyMISPRemoveFileHashIndicators(shd256_dict):
   
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

        if len(sha256_value) > 0:
            shd256_dict.pop([sha256_value])
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
                        case _:
                            if debugindicators: print("-- Identified Unknown Value:" + ioc_type)  


        if len(sha256_value) > 0:
            shd256_dict.pop([sha256_value])
            if debugindicators: print("Removed Deleted hash:" + sha256_value  )

        
    return  shd256_dict