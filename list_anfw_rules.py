import boto3
from botocore.exceptions import ClientError
import json
import argparse
import os
import csv
from tabulate import tabulate

# Add command-line arguments for region and role to assume within accounts
parser = argparse.ArgumentParser(description="Get AWS Network Firewall Rule Listing Python Script - Arguments")
parser.add_argument("-r", "--region", default="us-east-1", type=str, help="AWS Region")
parser.add_argument("-n", "--firewall-name", type=str, help="Name of the AWS network firewall to list the rules for")
parser.add_argument("-a", "--firewall-arn", type=str, help="ARN of the AWS network firewall to list the rules for")
parser.add_argument("-o", "--output-file", default="anfw_rules.csv", type=str, help="File to write rule groups to")
parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
parser.add_argument("-t", "--text", action="store_true", help="Print output in text format")
args=parser.parse_args()

# Data elements
stateful_rule_headers = [
    'FirewallName',
    'RuleGroupPriority',
    'RuleGroupName',
    'Action',
    'Direction',
    'Protocol',
    'Source',
    'SourcePort',
    'Destination',
    'DestinationPort',
    'Sid'
]
stateful_rule_values = []
stateful_rules_list = []

domain_rule_headers = [
    'FirewallName',
    'RuleGroupPriority',
    'RuleGroupName',
    'Action',
    'Domain',
]
domain_rule_values = []
domain_rules_list = []

# Get the Current Account ID and role and print to screen
caller_identity = boto3.client('sts').get_caller_identity()
current_account_id = caller_identity['Account']
current_role = caller_identity['Arn']

if (args.verbose):
    print(f"Current Account ID: {current_account_id}")
    print(f"Current Role: {current_role}")

# Initiate the boto3 client for AWS Network Firewall:
anfw = boto3.client('network-firewall')

# Call the "Describe_Firewall" API to obtain the firewall details and firewall policy arn:
if (args.firewall_name):
    describe_firewall_response = anfw.describe_firewall(FirewallName=args.firewall_name)
elif (args.firewall_arn):
    describe_firewall_response = anfw.describe_firewall(FirewallArn=args.firewall_arn)
else:
    print("You must specify either a firewall ARN or a firewall name.")
    print("please use the '-h' flag for help and more options.")
    exit()
anfw_firewall_name = describe_firewall_response['Firewall']['FirewallName']
anfw_firewall_arn = describe_firewall_response['Firewall']['FirewallArn']
anfw_policy_arn = describe_firewall_response['Firewall']['FirewallPolicyArn']
print(f"Firewall Name: {anfw_firewall_name}")
print(f"Firewall ARN: {anfw_firewall_arn}")

# Call the "Describe_Firewall_Policy" API to obtain the rule group references:
describe_firewall_policy_response = anfw.describe_firewall_policy(FirewallPolicyArn=anfw_policy_arn)

# If the firewall policy has stateless rule group references, print the rule group arns and priorities:
if 'StatelessRuleGroupReferences' in describe_firewall_policy_response['FirewallPolicy']:
    if (args.verbose): print("Stateless Rule Group References:")
    for stateless_rg_ref in describe_firewall_policy_response['FirewallPolicy']['StatelessRuleGroupReferences']:
        stateless_rg_arn = stateless_rg_ref['ResourceArn']
        stateless_rg_priority = stateless_rg_ref['Priority']
        if (args.verbose): print(f"  {stateless_rg_arn}")
        if (args.verbose): print(f"  {stateless_rg_priority}")
        describe_rule_group_response = anfw.describe_rule_group(RuleGroupArn=stateless_rg_ref['ResourceArn'])
        # TODO : The Stateless Rule Groups section is currently unfinished

# If the firewall policy has stateful rule group references, print the rule group arns and priorities, and store the rule details in a list:
if 'StatefulRuleGroupReferences' in describe_firewall_policy_response['FirewallPolicy']:
    if (args.verbose): print("Stateful Rule Group References:")
    for stateful_rg_ref in describe_firewall_policy_response['FirewallPolicy']['StatefulRuleGroupReferences']:
        stateful_rg_arn = stateful_rg_ref['ResourceArn']
        stateful_rg_priority = stateful_rg_ref['Priority']
        if (args.verbose): print(f"  {stateful_rg_arn}")
        if (args.verbose): print(f"  {stateful_rg_priority}")
        describe_rule_group_response = anfw.describe_rule_group(RuleGroupArn=stateful_rg_ref['ResourceArn'])
        stateful_rg_name = describe_rule_group_response['RuleGroupResponse']['RuleGroupName']
        if 'StatefulRules' in describe_rule_group_response['RuleGroup']['RulesSource']:
            if (args.verbose): print("Stateful Rules")
            for stateful_rule in describe_rule_group_response['RuleGroup']['RulesSource']['StatefulRules']:
                stateful_rule_values = [
                    anfw_firewall_name,
                    stateful_rg_priority,
                    stateful_rg_name,
                    stateful_rule['Action'],
                    stateful_rule['Header']['Direction'],
                    stateful_rule['Header']['Protocol'],
                    stateful_rule['Header']['Source'],
                    stateful_rule['Header']['SourcePort'],
                    stateful_rule['Header']['Destination'],
                    stateful_rule['Header']['DestinationPort'],
                ]

                if 'RuleOptions' in stateful_rule:
                    for keyword in stateful_rule['RuleOptions']:
                        if 'Keyword' in keyword and keyword['Keyword'] == 'sid':
                            stateful_rule_values.append(keyword['Settings'][0])
                    
                stateful_rules_list.append(stateful_rule_values)

                if (args.verbose): print("Stateful Rule: ")
                if (args.verbose): print(stateful_rule_values)
        elif 'RulesSourceList' in describe_rule_group_response['RuleGroup']['RulesSource']:
            if (args.verbose): print("Domain Rules")
            for target in describe_rule_group_response['RuleGroup']['RulesSource']['RulesSourceList']['Targets']:
                domain_rule_values = [
                    anfw_firewall_name,
                    stateful_rg_priority,
                    stateful_rg_name,
                    describe_rule_group_response['RuleGroup']['RulesSource']['RulesSourceList']['GeneratedRulesType'],
                    target
                ]
                domain_rules_list.append(domain_rule_values)


print("----------------------------------------")
print("AWS Network Firewall rule listing is complete")
print(f"Total number of stateful rules: {len(stateful_rules_list)}")
print(f"Total number of domain rules: {len(domain_rules_list)}")

# Write AWS Network Firewall Rules to file
with open(args.output_file, 'w') as csvfile:
    anfw_csv_writer = csv.writer(csvfile)
    anfw_csv_writer.writerow(stateful_rule_headers)
    if (args.verbose): print(stateful_rule_headers)
    for row in stateful_rules_list:
        anfw_csv_writer.writerow(row)
        if (args.verbose): print(row)
    print(f"CSV output (stateful rules) is saved at: {os.getcwd()}/{args.output_file}")

# Write AWS Network Firewall Rules to file
with open("anfw_domains.csv", 'w') as csvfile:
    anfw_csv_writer = csv.writer(csvfile)
    anfw_csv_writer.writerow(domain_rule_headers)
    if (args.verbose): print(domain_rule_headers)
    for row in domain_rules_list:
        anfw_csv_writer.writerow(row)
        if (args.verbose): print(row)
    print(f"CSV output (domains) is saved at: {os.getcwd()}/anfw_domains.csv")


if (args.text):
    with open("anfw_rules.txt", "w") as text_file:
        text_file.write(tabulate(stateful_rules_list, headers=stateful_rule_headers, tablefmt="grid"))
        text_file.write(tabulate(domain_rules_list, headers=domain_rule_headers, tablefmt="grid"))
    if (args.verbose): print(tabulate(stateful_rules_list, headers=stateful_rule_headers, tablefmt="grid"))
    if (args.verbose): print(tabulate(domain_rules_list, headers=domain_rule_headers, tablefmt="grid"))
    print(f"Text output is saved at: {os.getcwd()}/anfw_rules.txt")
    
#if error_list:
#    with open("errors.txt", "w") as error_file:
#        for error in error_list:
#            error_file.write(f"\n{error}")
#    print(f"The following {len(account_ids_failed)} accounts encountered errors:")
#    print(account_ids_failed)
#    print(f"{len(error_list)} errors occurred. Error messages are located at: {os.getcwd()}/errors.txt")