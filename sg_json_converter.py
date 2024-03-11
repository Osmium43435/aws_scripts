import json
import csv
import argparse
import os
from pprint import pprint 

parser = argparse.ArgumentParser(description="Convert Security Groups JSON to CSV/TXT Script - Arguments")
parser.add_argument("-i", "--input-file", default="security_groups.json", type=str, help="File to read security groups from")
parser.add_argument("-o", "--output-file", default="security_groups.csv", type=str, help="File to write CSV security groups to")
parser.add_argument("-t", "--text", action="store_true", help="Generate a text output also with Tabulate")
parser.add_argument("-j", "--json", action="store_true", help="Generate a simplified JSON output")
parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
args=parser.parse_args()

# If text output is desired, import the tabulate library
if args.text:
    from tabulate import tabulate

# Open the input file
with open(args.input_file, 'r') as sg_json:
    all_accounts_json = json.loads(sg_json.read())

# Create list to store security group rule dicts
rules_list_of_dicts = []

sec_group_count = 0 # Counter to hold the number of security groups identified in all accounts
# Iterate through json file (list of dicts: security groups per account+region)
for single_account_json in all_accounts_json:
    account_security_groups = single_account_json["SecurityGroups"]
    sec_group_count += len(account_security_groups) # Add to the counter, the number of security groups in this account/region
    for security_group in account_security_groups:
        # Initialize Rule Dict
        rule = {
            "account": "",
            "sec_group_id": "",
            "sec_group_name" : "",
            "sec_group_description": "",
            "direction": "",
            "protocol": "",
            "ip_ranges": "",
            "src_port": "",
            "dst_port": ""
        }

        # This main section will be the same for each security group
        rule["sec_group_description"] = security_group["Description"][:50]
        rule["sec_group_name"] = security_group["GroupName"]
        rule["sec_group_id"] = security_group["GroupId"]
        rule["account"] = security_group["OwnerId"]

        # Iterate through inbound permissions in the security group
        if "IpPermissions" in security_group:
            for inbound_rule in security_group["IpPermissions"]:
                # Set Inbound direction and reset ports
                rule["direction"] = "Inbound"
                rule["src_port"] = ""
                rule["dst_port"] = ""
                
                # Set Src Port
                if "FromPort" in inbound_rule:
                    rule["src_port"] = str(inbound_rule["FromPort"])
                else:
                    rule["src_port"] = "Any"
                
                # Set Dest Port
                if "ToPort" in inbound_rule:
                    rule["dst_port"] = str(inbound_rule["ToPort"])
                else:
                    rule["dst_port"] = "Any"
                
                # Set Protocol
                rule["protocol"] = inbound_rule["IpProtocol"]
                if rule["protocol"] == "-1":
                    rule["protocol"] = "Any"
                elif rule["protocol"] == "6":
                    rule["protocol"] = "TCP"
                elif rule["protocol"] == "17":
                    rule["protocol"] = "UDP"        

                # Set IP CIDR Ranges (may be multiple)
                rule["ip_ranges"] = ""
                if inbound_rule["IpRanges"]:
                    for range in inbound_rule["IpRanges"]:
                        description_range = ""
                        if "Description" in range:
                            description_range = " ({})".format(range["Description"])                
                        rule["ip_ranges"] = "{} {}{}".format(rule["ip_ranges"], range["CidrIp"], description_range)
                else:
                    if inbound_rule["UserIdGroupPairs"]:
                        for sg_id in inbound_rule["UserIdGroupPairs"]:
                            rule["ip_ranges"] = "{} {}".format(rule["ip_ranges"], sg_id["GroupId"])
                    else:
                        rule["ip_ranges"] = "Any"

                # Add rule to list
                updated_rule_dict = dict(rule)
                rules_list_of_dicts.append(updated_rule_dict)

        # Iterate through outbound permissions in the security group
        if security_group["IpPermissionsEgress"]:
            for outbound_rule in security_group["IpPermissionsEgress"]:
                # Set Outbound direction and reset ports
                rule["direction"] = "Outbound"
                rule["src_port"] = ""
                rule["dst_port"] = ""

                # Set Source Port
                if "FromPort" in outbound_rule:
                    rule["src_port"] = str(outbound_rule["FromPort"])
                else:
                    rule["src_port"] = "Any"                
                
                # Set Destination Port
                if "ToPort" in outbound_rule:
                    rule["dst_port"] = str(outbound_rule["ToPort"])
                else:
                    rule["dst_port"] = "Any"                
                
                # Set Protocol
                rule["protocol"] = outbound_rule["IpProtocol"]
                if rule["protocol"] == "-1":
                    rule["protocol"] = "Any"
                elif rule["protocol"] == "6":
                    rule["protocol"] = "TCP"
                elif rule["protocol"] == "17":
                    rule["protocol"] = "UDP"            
                
                # Set IP CIDR Range (may be multiple)
                rule["ip_ranges"] = ""
                if outbound_rule["IpRanges"]:
                    for range in outbound_rule["IpRanges"]:
                        description_range = ""
                        if "Description" in range:
                            description_range = " ({})".format(range["Description"])
                        rule["ip_ranges"] = "{} {}{}".format(rule["ip_ranges"], range["CidrIp"], description_range)
                        if not range["CidrIp"]:
                            rule["ip_ranges"] = "Any"
                else:
                    if outbound_rule["UserIdGroupPairs"]:
                        for sg_id in outbound_rule["UserIdGroupPairs"]:
                            rule["ip_ranges"] = "{} {}".format(rule["ip_ranges"], sg_id["GroupId"])
                    else:
                        rule["ip_ranges"] = "Any"

                # Add rule to lists
                updated_rule_dict = dict(rule)
                rules_list_of_dicts.append(updated_rule_dict)

# Create list of headers for writing to CSV and TXT file
csv_headers = [
    "account",
    "sec_group_id",
    "sec_group_name",
    "sec_group_description",
    "direction",
    "protocol",
    "ip_ranges",
    "src_port",
    "dst_port"
]

# Write the security group rules to a CSV file
with open(args.output_file, 'w') as csv_file:
    csv_writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
    csv_writer.writeheader()
    if args.verbose:
        print(csv_headers)
    for row in rules_list_of_dicts:
        csv_writer.writerow(row)
        if args.verbose:
            print(list(row.values()))

# If text output is desired, output the security group rules to text file and print to screen to screen, via tabulate
if args.text:
    rules_list_of_values = [list(rule.values()) for rule in rules_list_of_dicts]
    with open('security_groups.txt', 'w') as sg_text:
        sg_text.write(tabulate(rules_list_of_values, csv_headers, tablefmt="grid"))
    if args.verbose:
        print(tabulate(rules_list_of_values, csv_headers, tablefmt="grid"))
    
# If simplified JSON is desired, output the security group rules to json
if args.json:
    with open('security_groups_simplified.json', 'w') as simplified_json:
        json.dump(rules_list_of_dicts, simplified_json, indent=4)
    if args.verbose:
        pprint(rules_list_of_dicts)

print(f"Identified {len(rules_list_of_dicts)} rules across {sec_group_count} security groups")
print(f"CSV output saved at: {os.getcwd()}/{args.output_file}")
if args.text:
    print(f"Text output saved at: {os.getcwd()}/security_groups.txt")
if args.json:
    print(f"Simplified JSON output saved at: {os.getcwd()}/security_groups_simplified.json")