import pandas as pd 
import postprocessing
import json

#  Data dictionaries


types = {
"Connection to Malicious URL for malware_download": "INITIAL ACCESS",
    "Event Triggered Execution": "EXECUTION",
    "Persistence - Registry Key Manipulation": "PERSISTENCE",
    "Privilege Escalation - Exploiting Vulnerability": "PRIVILEGE ESCALATION",
    "Defense Evasion - Signature-based Evasion": "DEFENSE EVASION",
    "Credential Access - Password Guessing" : "CREDENTIAL ACCESS",
    "Discovery - Network Service Scanning": "DISCOVERY",
    "Lateral Movement - Remote Desktop Protocol (RDP) Exploitation": "LATERAL MOVEMENT",
    "Collection - Data Exfiltration via Email": "COLLECTION",
    "Command and Control - Communication over Tor Network": "COMMAND AND CONTROL",
    "Exfiltration - File Transfer to External Server": "EXFILTRATION",
    "Impact - Denial-of-Service (DoS) Attack": "IMPACT"
}


Attack_stages = {

    "Initial": [
        ['INITIAL ACCESS', 'EXECUTION'],
        ['INITIAL ACCESS', 'EXECUTION', 'PERSISTENCE'],
        ['INITIAL ACCESS', 'CREDENTIAL ACCESS', 'DISCOVERY']
        ],
    "Partial": [
        ['PERSISTENCE', 'PRIVILEGE ESCALATION', 'CREDENTIAL ACCESS', 'DISCOVERY']
    ],

    "Complete": [
        ['INITIAL ACCESS', 'EXECUTION', 'PERSISTENCE', 'PRIVILEGE ESCALATION', 'DEFENSE EVASION', 'CREDENTIAL ACCESS', 'DISCOVERY', 'LATERAL MOVEMENT', 'COLLECTION', 'COMMAND AND CONTROL', 'IMPACT'],
        ['INITIAL ACCESS', 'EXECUTION', 'DEFENSE EVASION', 'EXFILTRATION', 'IMPACT'],
        ['PERSISTENCE', 'CREDENTIAL ACCESS', 'COLLECTION', 'EXFILTRATION']
    ]

    
}




# Execution

data = pd.read_csv("Data/Cleaned/Test_test_dataset.csv")
data['cluster'] = data['pred_cluster']

addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
usernames = ["SourceHostName","DeviceHostName","DestinationHostName"]

correlated_factors = postprocessing.get_feature_chains(data, usernames, addresses)

compiled_output = []
customerName = list(set(data['CustomerName']))[0]


clusters = data.groupby('cluster')

for c_no, cluster in clusters:
    start_date = min(cluster['EndDate'])
    end_date = max(cluster['EndDate'])
    subattack_types = list(set(cluster['MalwareIntelAttackType']))
    tactics = list(set([types[description] for description in subattack_types]))
    stage = []
    device_addresses = list(set(cluster['DeviceAddress']))
    print("cluster" , c_no)

    for attack_chain in tactics:
        if attack_chain in Attack_stages["Complete"]:
            stage.append("Potential Hit")
        elif attack_chain in Attack_stages['Partial']:
            stage.append("Partial")
        elif attack_chain in Attack_stages["Initial"]:
            stage.append("Initial")
        else:
            stage.append("Other")
    

    json_obj = {
        "start_date": start_date,
        "end_date": end_date,
        "correlationFactor": correlated_factors[c_no],
        "CustomerName": customerName,
        "SubAttackType": subattack_types,
        "DeviceAddress": device_addresses,
        "Tactic": tactics,
        "Scenario_type": stage[0]
    }
    compiled_output.append(json_obj)

print(compiled_output)

path = "output.json"
with open(path, 'w') as file:
    json.dump(compiled_output, file, indent=4)




