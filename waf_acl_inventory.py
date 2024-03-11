import boto3
from botocore.exceptions import ClientError
import json
import argparse
import os
import csv

# Add command-line arguments for region and role to assume within accounts
parser = argparse.ArgumentParser(description="Get WAF Web ACLs Cross-Account Python Script - Arguments")
parser.add_argument("-r", "--region", default="us-east-1", type=str, help="AWS Region")
parser.add_argument("-o", "--organization", action="store_true", help="If specified, execute across all accounts in AWS Organization")
parser.add_argument("-a", "--assumed-role", default="ReadOnlyRole", type=str, help="Role to assume in each organization account")
parser.add_argument("-f", "--file", default="waf_web_acls.csv", type=str, help="File to write WAF web acls to")
parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
args=parser.parse_args()

# Get the Current Account ID and role and print to screen
caller_identity = boto3.client('sts').get_caller_identity()
current_account_id = caller_identity['Account']
current_role = caller_identity['Arn']

if (args.verbose):
    print(f"Current Account ID: {current_account_id}")
    print(f"Current Role: {current_role}")

# Configure the list of regions to iterate through, and print to screen.
regions = [
    # Add any additional regions you want to check here.
    # Regions that are denied by SCPs will cause the script to fail.
]
if args.region not in regions:
    regions.insert(0, args.region)

if (args.verbose):
    print("Regions selected:")
    print(regions)

# Create a list object to hold the waf web acls in each account:
waf_list_of_values = [] # List to hold the list of values for each row in the customized waf output
total_webacl_count = 0 # Counter to hold the total number of WAF Web ACLs identified
webacl_count_account = 0 # Counter to hold the number of WAF Web ACLs identified in each account
webacl_count_dict = {} # Dict to hold the number of WAF Web ACLs per account

# Capture WAF Web ACLs for the current account: 

webacl_count_account = 0
for region in regions:
    if args.verbose: print(f"Identifying WAF web ACLs within account {current_account_id}, region {region}...")
    client = boto3.client('wafv2', region_name=region)
    regional_waf = client.list_web_acls(Scope='REGIONAL')
    if regional_waf['WebACLs']:
        for acl in regional_waf['WebACLs']:
            waf_row_list = [current_account_id, region, acl['Name'], acl['Id'], acl['Description'], acl['ARN']]
            waf_list_of_values.append(waf_row_list)
        webacl_count_region = len(regional_waf['WebACLs'])
        webacl_count_account += webacl_count_region
        if args.verbose: print(f"Identified {webacl_count_region} Web ACLs in account {current_account_id} region {region}.")
client = boto3.client('wafv2', region_name='us-east-1')
cf_waf = client.list_web_acls(Scope='CLOUDFRONT')
if cf_waf['WebACLs']: 
    for acl in cf_waf['WebACLs']:
        waf_row_list = [current_account_id, 'CLOUDFRONT', acl['Name'], acl['Id'], acl['Description'], acl['ARN']]
        waf_list_of_values.append(waf_row_list)
    webacl_count_region = len(cf_waf['WebACLs'])
    webacl_count_account += webacl_count_region
    if args.verbose: print(f"Identified {webacl_count_region} Global/CloudFront Web ACLs in account {current_account_id}.")
total_webacl_count += webacl_count_account
webacl_count_dict[current_account_id] = webacl_count_account
if args.verbose: print(f"Found {webacl_count_account} WAF Web ACLs in account {current_account_id}")

if args.verbose: print("Completed identification of WAF Web ACLs in the current account")

# ---------- Cross-account functionality below ----------- 
account_ids = [] # List to hold account IDs to iterate through
error_list = [] # List to hold errors encountered
account_ids_scanned = [current_account_id] # List to hold account IDs that have been scanned
account_ids_failed = [] # List to hold account IDs that failed to scan

# If organization / cross-account capabilities are selected, execute across all accounts by assuming roles and appending to the same file:
if (args.organization == True):
    # Create a list of AWS Account IDs in the AWS Organization, and print to screen
    try:
        organizations_client = boto3.client('organizations')
        account_list = organizations_client.list_accounts()
        for account in account_list['Accounts']:
            if account['Id'] != current_account_id:
                account_ids.append(account['Id'])
    except ClientError as error: 
        print(f"Couldn't retrieve account IDs from AWS Organization. Here's why: {error.response['Error']['Message']}")
        error_list.append(error.response['Error']['Message'])
    else:
        if args.verbose: print(f"{len(account_ids)} additional accounts found in your AWS Organization: ")
        if args.verbose: print(account_ids)

        # Iterate through account Ids and regions, capturing WAF Web ACLs
        for account_id in account_ids:
            if account_id is not current_account_id:
                webacl_count_account = 0 # Reset WAF per-account counter
                if args.verbose: print(f"Assuming role {args.assumed_role} in account {account_id}...")
                try:
                    # Assume role_name in each account and get temporary credentials (can use OrganizationAccountAccessRole but it is admin-level, advised to create/utilize read-only roles for this purposes)
                    sts_client = boto3.client('sts')
                    sts_response = sts_client.assume_role(RoleArn=f"arn:aws:iam::{account_id}:role/{args.assumed_role}", RoleSessionName="ListWAFInventoryScript")
                    temp_credentials = sts_response['Credentials']
                    assumed_session = boto3.Session(                                                                                                                   
                        aws_access_key_id=temp_credentials['AccessKeyId'],                                                                                             
                        aws_secret_access_key=temp_credentials['SecretAccessKey'],                                                                                     
                        aws_session_token=temp_credentials['SessionToken']
                    )
                except ClientError as error:
                    error_list.append(error.response['Error']['Message'])
                    account_ids_failed.append(account_id)
                    print(f"Couldn't assume role. Here's why: {error.response['Error']['Message']}")
                    print(f"Skipping account {account_id}")
                else:
                    # Capture WAF Web ACLs for the current account in each region iteratively, and append to the list
                    account_ids_scanned.append(account_id)
                    for region in regions:
                        if args.verbose: print(f"Identifying WAF web ACLs within account {current_account_id}, region {region}...")
                        client = assumed_session.client('wafv2', region_name=region)
                        regional_waf = client.list_web_acls(Scope='REGIONAL')
                        if regional_waf['WebACLs']:
                            for acl in regional_waf['WebACLs']:
                                waf_row_list = [account_id, region, acl['Name'], acl['Id'], acl['Description'], acl['ARN']]
                                waf_list_of_values.append(waf_row_list)
                            webacl_count_region = len(regional_waf['WebACLs'])
                            webacl_count_account += webacl_count_region
                            if args.verbose: print(f"Identified {webacl_count_region} Web ACLs in account {current_account_id} region {region}.")
                    client = assumed_session.client('wafv2', region_name='us-east-1')
                    cf_waf = client.list_web_acls(Scope='CLOUDFRONT')
                    if cf_waf['WebACLs']:
                        for acl in cf_waf['WebACLs']:
                            waf_row_list = [account_id, 'CLOUDFRONT', acl['Name'], acl['Id'], acl['Description'], acl['ARN']]
                            waf_list_of_values.append(waf_row_list)
                        webacl_count_region = len(cf_waf['WebACLs'])
                        webacl_count_account += webacl_count_region
                        if args.verbose: print(f"Identified {webacl_count_region} Global/CloudFront Web ACLs in account {current_account_id}.")
                total_webacl_count += webacl_count_account
                webacl_count_dict[account_id] = webacl_count_account

waf_headers = [
    'Account_ID',
    'Region',
    'Web_ACL_Name',
    'Web_ACL_ID',
    'Web_ACL_Description',
    'Web_ACL_ARN'
]

# Write WAF Web ACLs to csv file
with open(args.file, 'w', newline="") as wafcsvfile:
    writer = csv.writer(wafcsvfile)
    writer.writerow(waf_headers)
    if args.verbose: print(waf_headers)
    for row in waf_list_of_values:
        writer.writerow(row)
        if args.verbose: print(row)

print("----------------------------------------")
print("AWS WAF Web ACL inventory is complete")
print(f"{total_webacl_count} Web ACLs were identified in {sum(value != 0 for value in webacl_count_dict.values())} accounts")
print(f"The following {len(account_ids_scanned)} accounts and regions were scanned: ")

print("Accounts:")
print(account_ids_scanned)
print("Regions:")
print(regions)

if args.verbose: 
    print("Number of WAF Web ACLs identified in each account:")
    print(webacl_count_dict)

if error_list:
    with open("errors.txt", "w") as error_file:
        for error in error_list:
            error_file.write(f"\n{error}")
    print(f"The following {len(account_ids_failed)} accounts encountered errors:")
    print(account_ids_failed)
    print(f"{len(error_list)} errors occurred. Error messages are located at: {os.getcwd()}/errors.txt")

print(f"CSV output is saved at: {os.getcwd()}/{args.file}")
