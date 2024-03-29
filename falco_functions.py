import os
import yaml
from config import *
import sys
import csv

##############################################
#  Check if Falco rules files exist          #
#    - if they don't create the file         #
#    - returns file handles                  #
##############################################

def checkFalcoRulesFilesExists():
    
    try:
        if not os.path.isfile(falco_ipv4_rules_file):
            if debug == True: print(" - File " + falco_ipv4_rules_file + " didn't exist - creating it.")
            f = open(falco_ipv4_rules_file,"a")
            f.write("# This Falco rules file is autogenerated by falco-taxii-stix-connect - please do not alter manually\n")
            f.write("- list: malicious_ip_list\n")
            f.write("  items: []\n")
            f.close()
    except Exception as err:
        print(f"Couldn't create Falco rules file " + falco_ipv4_rules_file + ". Please check the directory exists. Error: {err=}, {type(err)=}")
        sys.exit(0)
    

    try:
        if not os.path.isfile(falco_domain_rules_file):
            if debug == True: print(" - File " + falco_domain_rules_file + " didn't exist - creating it.")
            f = open(falco_domain_rules_file,"a")
            f.write("# This Falco rules file is autogenerated by falco-taxii-stix-connect - please do not alter manually\n")
            f.write("- list: malicious_domain_list\n")
            f.write("  items: []\n")
            f.close()
    except Exception as err:
        print(f"Couldn't create Falco rules file " + falco_domain_rules_file + ". Please check the directory exists. Error: {err=}, {type(err)=}")
        sys.exit(0)

    
    try:
        if not os.path.isfile(falco_malware_hash_file):
            if debug == True: print(" - File " + falco_malware_hash_file + " didn't exist - creating it.")
            f = open(falco_malware_hash_file,"a")
            f.write("")
            f.close()
    except Exception as err:
        print(f"Couldn't create Falco rules file " + falco_malware_hash_file + ". Please check the directory exists. Error: {err=}, {type(err)=}")
        sys.exit(0)

##############################################
#  Open Falco Rules file and read as YAML    #
#    - returns a PyYAML object               #
##############################################

def returnFalcoRulesFileYaml(rules_file):
    with open(rules_file, "r") as stream:
        try:
            rules_file_yaml = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(f"- WARNING: Couldn't read Falco rules file " + rules_file + ". Please check the file exists, is readable and is YAML formatted. Error {err=}, {type(err)=}")
            rules_file_yaml[0] = {'items': ''}
    stream.close()
    return rules_file_yaml


#################################################
#  Open Falco Rules file and write YAML output  #
#    - returns a PyYAML object                  #
#################################################

def writeFalcoRulesFileYaml(rules_file, list_name, yaml_string):
    try:
        with open(rules_file, "w") as stream:
            f = open(rules_file,"w")
            f.write("# This Falco rules file is autogenerated by falco-taxii-stix-connect - please do not alter manually\n")
            f.write("- list: " + list_name + "\n")
            f.write("  items: " + yaml_string + "\n")
        f.close()
    except yaml.YAMLError as exc:
            print(f"Couldn't write Falco rules file " + rules_file + ". Please check the file exists, is readable and is YAML formatted. Error {err=}, {type(err)=}")
            sys.exit(0)
    return 
    
##############################################
#  Write CSV File                            #
#      - no return value                     #
##############################################
def writeFalcoCSVFile(input_dict, filename):
    
    try:
        with open(filename, 'w', newline='\n') as file:
            writer = csv.writer(file)
            for hash in input_dict.keys():
                writer.writerow([hash,str(input_dict[hash][0])])
    except Exception as err:
        print(f"- WARNING: Couldn't write Falco malware hash file: " + filename + ".  Error {err=}, {type(err)=}")
    
##############################################
#  Read CSV File                             #
#      - no return value                     #
##############################################
def readFalcoCSVFile(filename):
    
    sha256_dict = {}
    try:
        with open(filename, newline='\n') as csvfile:
            malwareHashCSV = csv.reader(csvfile, delimiter=',')
            for row in malwareHashCSV:
                sha256_dict[row[0]] = [row[1],'','']
    except Exception as err:
        print(f"- WARNING: Couldn't parse Falco malware hash file: " + filename + " from CSV.  Error {err=}, {type(err)=}")
    
    return sha256_dict

