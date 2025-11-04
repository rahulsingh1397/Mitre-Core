import copy
from datetime import timedelta
import datetime
import json
import random
import string
import sys
import time
import postprocessing
import preprocessing

import pandas as pd



phases = [
    "Connection to Malicious URL for malware_download",
    "Event Triggered Execution",
    "Persistence - Registry Key Manipulation",
    "Privilege Escalation - Exploiting Vulnerability",
    "Defense Evasion - Signature-based Evasion",
    "Credential Access - Password Guessing",
    "Discovery - Network Service Scanning",
    "Lateral Movement - Remote Desktop Protocol (RDP) Exploitation",
    "Collection - Data Exfiltration via Email",
    "Command and Control - Communication over Tor Network",
    "Exfiltration - File Transfer to External Server",
    "Impact - Denial-of-Service (DoS) Attack"
]

def generate_random_sequence():
    length = random.randint(3, 12)  # Random length from 3 to 12
    sequence = sorted(random.sample(range(12), length))
    return sequence

def generate_random_name(length=8):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))

def generate_random_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

def increment_date(date_string, days_to_add=1):
    date =  datetime.datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f%z")
    new_date = date + timedelta(days=days_to_add)
    return new_date.isoformat()

def find_ind(val,list):
    counter = 0
    for i in list:
        if i == val:
            return counter
        i += 1
    return None

def create_attack(prev_attack, IP_shared, seq):

    if not seq:
        return None,None
    obj = {}
    obj['SourceAddress'] = generate_random_ip()
    obj['DeviceAddress'] = generate_random_ip()
    obj['DestinationAddress'] = generate_random_ip()
    obj['SourceHostName'] = generate_random_name()
    obj['DeviceHostName'] = generate_random_name()
    obj['DestinationHostName'] = generate_random_name()

    if prev_attack:
        
        ip = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
        ip_val = [obj["SourceAddress"],obj["DestinationAddress"],obj["DeviceAddress"]]
        names = ["SourceHostName","DeviceHostName","DestinationHostName"]
        idx_with_shared_ip = random.randint(0, 2)
        obj[ip[idx_with_shared_ip]] = IP_shared

        new_json = copy.deepcopy(prev_attack)  # Create a new JSON based on the previous attack
        
        # Increment the EndDate by the specified number of days
        new_json["investigation_selection"]["EndDate"] = increment_date(prev_attack["investigation_selection"]["EndDate"], 1)
        
        # Assign new IP addresses to the relevant fields
        new_json["investigation_selection"]["DeviceAddress"] = obj["DeviceAddress"]
        new_json["investigation_selection"]["SourceAddress"] = obj["SourceAddress"]
        new_json["investigation_selection"]["DestinationAddress"] = obj["DestinationAddress"]
        new_json["investigation_selection"]['SourceHostName'] = obj['SourceHostName']
        new_json["investigation_selection"]['DeviceHostName'] = obj['DeviceHostName']
        new_json["investigation_selection"]['DestinationHostName'] = obj['DestinationHostName']
        
        # Check if previous source address matches new destination address
        if prev_attack["investigation_selection"]["SourceAddress"] in ip_val:
            ind = find_ind(prev_attack["investigation_selection"]["SourceAddress"],ip_val)
            new_json["investigation_selection"][names[ind]] = prev_attack["investigation_selection"]["SourceHostName"]
        
        # Check if previous device address matches new destination address
        if prev_attack["investigation_selection"]["DeviceAddress"] in ip_val:
            ind = find_ind(prev_attack["investigation_selection"]["DeviceAddress"],ip_val)
            new_json["investigation_selection"][names[ind]] = prev_attack["investigation_selection"]["DeviceHostName"]

        if prev_attack["investigation_selection"]["DestinationAddress"] in ip_val:
            ind = find_ind(prev_attack["investigation_selection"]["DestinationAddress"],ip_val)
            new_json["investigation_selection"][names[ind]] = prev_attack["investigation_selection"]["DestinationHostName"]

        # Set the new phase for the attack
        x = seq.pop(0)
        
        new_json["investigation_selection"]["MalwareIntelAttackType"] = phases[x]

    else:
        new_json =  {
    "_id" : "6295fd421208222c45df5502",
    "DataId" : "b13d5d3b-03f4-4f50-9d04-f9bacf16b25e",
    "AlertId" : "CR062000027921",
    "investigation_selection" : {
        "MalwareIntelAttackType" : phases[seq.pop(0)],
        "DeviceVendor" : "Fortinet",
        "DeviceProduct" : "Fortigate",
        "DeviceSeverity" : "Low",
        "DeviceEventCategory" : "utm:webfilter",
        "DeviceSeverityNum" : "notice",
        "DeviceAction" : "passthrough",
        "DeviceAddress" : obj["DeviceAddress"],
        "DeviceHostName" : obj["DeviceHostName"],
        "RequestURL" : "http://crl.pki.goog/gsr1/gsr1.crl",
        "RequestMethod" : "direct",
        "EndDate" : '2023-11-28T15:23:45.678+0530',
        "CategoryOutcome" : "/Failure",
        "CategoryBehavior" : "/Access",
        "CommunicationType" : "Inbound",
        "SourceHostName" : obj["SourceHostName"],
        "SourceAddress" : obj['SourceAddress'],
        "DestinationHostName" : obj["DestinationHostName"],
        "DestinationAddress" : obj["DestinationAddress"],
        "DestinationZoneURI" : "/All Zones/ArcSight System/Public Address Space Zones/ARIN/142.0.0.0-144.255.255.255 (ARIN)",
        "CustomerName" : "CANARAROBECO",
        "DestinationLatitude" : "37.405991",
        "DestinationLongitude" : "-122.078514",
        "DestinationCity" : "Mountain View",
        "DestinationCountry" : "United States of America"
    },
    "customerName" : "CANARAROBECO",
    "createdDate" : "2022-05-31T05:04:26.813-06:30",
    "lastModifiedDate" : "2022-05-31T05:16:20.978-06:30",
    "alertEvidences" : [ 
        "CR053000027918", 
        "CR062000027921", 
        "CR053000027790", 
        "CR062000027795", 
        "CR053000025435", 
        "CR062000025436"
    ],
    "evidenceColumns" : [ 
        "", 
        "AlertId", 
        "SourceAddress", 
        "SourceHostName", 
        "SourcePort", 
        "SourceUserName", 
        "SourceGTIThreatRiskScore", 
        "DestinationAddress", 
        "DestinationHostName", 
        "DestinationPort", 
        "DestinationUserName", 
        "DestinationGTIThreatRiskScore", 
        "AttackType", 
        "SubAttackType", 
        "RequestURL", 
        "DeviceVendor", 
        "DeviceProduct", 
        "Name", 
        "Message", 
        "CustomerName", 
        "EndDate", 
        "BaseEventCount", 
        "StartDate", 
        "DestinationProcessName", 
        "FileID", 
        "FileName", 
        "FileType", 
        "FilePath", 
        "ApplicationProtocol", 
        "TransportProtocol", 
        "DeviceAction", 
        "LogonType", 
        "Reason", 
        "CategoryBehavior", 
        "CategoryOutcome", 
        "SourceProcessName", 
        "VirusName", 
        "Severityscore", 
        "Countbaseevent", 
        "Countoflogs ", 
        "SourceLocation", 
        "SourceNetworkName", 
        "SourceZone", 
        "SourceCriticality", 
        "DestinationLocation", 
        "DestinationNetworkName", 
        "DestinationZone", 
        "DestinationCriticality"
    ]
}
    return new_json, seq


def create_attack_flow(path,n):

    attack_chains_generated = {}    
    for i in range(n):
                
            sequence = generate_random_sequence()
            attack_chain = []
            curr_attack = None
            while sequence:
                if not curr_attack:
                    curr_attack, sequence = create_attack(None,None,sequence)
                else:
                    curr_attack, sequence = create_attack(curr_attack,curr_attack["investigation_selection"][random.choice(['SourceAddress', 'DestinationAddress', 'DeviceAddress'])],sequence)

                if curr_attack:
                    attack_chain.append(curr_attack)
            
            attack_chains_generated[i] = attack_chain
            

    with open(path, 'w') as file:
        output = []
        for i in range(n):
            for attack in attack_chains_generated[i]:
                attack["investigation_selection"]["actual_cluster"] = i
            output = output + attack_chains_generated[i]    
        json.dump(output, file, indent=4)
                            
    return attack_chains_generated


# create dataset


def build_data(n =10):
    path = "Testing/test_incident.json"
    attack_chains_generated = create_attack_flow(path,n)

    data = None
    with open(path, 'r') as file:
        data = json.load(file)
        

    investigation_data_list = []

    # Extract 'investigation_selection' parts from each JSON object
    for obj in data:
        if 'investigation_selection' in obj:
            investigation_data_list.append(obj['investigation_selection'])

    # Convert to DataFrame
    df = pd.DataFrame(investigation_data_list)
    # df['cluster'] = 1

    # Display DataFrame
    # df.to_csv('Data/Raw_data/test_dataset.csv')
    return df

def main():
    print("hi")
    ## Testing
    build_data()
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Testing started at: " + str(current_time))

    postprocessing.main('Data/Raw_data/test_dataset.csv')
    preprocessing.main('Data/Raw_data/test_dataset.csv')

