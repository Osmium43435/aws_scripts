import json
import csv

with open("security_groups.json", 'r') as sg_json:
    all_accounts_json = json.loads(sg_json.read())

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

# Print headers to screen
print("| {0:12s} | {1:25s} | {2:30s} | {3:50s} | {4:10s} | {5:8s} | {6:50s} | {7:8s} | {8:8s} |".format(*csv_headers))
print("| ------------ | ------------------------- | ------------------------------ | -------------------------------------------------- | ---------- | -------- | -------------------------------------------------- | -------- | -------- |")

with open("security_groups.csv", 'w') as csv_file:
    csv_writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
    csv_writer.writeheader()

    for single_account_json in all_accounts_json:
        account_security_groups = single_account_json["SecurityGroups"]
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

                    # Write rule dict to csv:
                    csv_writer.writerow(rule)

                    # Print rule to screen
                    print("| {account:12s} | {sec_group_id:25s} | {sec_group_name:30s} | {sec_group_description:50s} | {direction:10s} | {protocol:8s} | {ip_ranges:50s} | {src_port:8s} | {dst_port:8s} |".format(**rule))

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

                    # Write rule dict to csv:
                    csv_writer.writerow(rule)

                    # Print rule to screen
                    print("| {account:12s} | {sec_group_id:25s} | {sec_group_name:30s} | {sec_group_description:50s} | {direction:10s} | {protocol:8s} | {ip_ranges:50s} | {src_port:8s} | {dst_port:8s} |".format(**rule))
print("| ------------ | ------------------------- | ------------------------------ | -------------------------------------------------- | ---------- | -------- | -------------------------------------------------- | -------- | -------- |")