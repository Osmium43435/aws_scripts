import boto3
from botocore.exceptions import ClientError
import json
import argparse
import os
import csv

# Add command-line arguments for region and role to assume within accounts
parser = argparse.ArgumentParser(description="Get KMS Keys Cross-Account Python Script - Arguments")
parser.add_argument("-r", "--region", default="us-east-1", type=str, help="AWS Region")
parser.add_argument("-o", "--organization", action="store_true", help="If specified, execute across all accounts in AWS Organization")
parser.add_argument("-a", "--assumed-role", default="ReadOnlyRole", type=str, help="Role to assume in each organization account")
parser.add_argument("-f", "--file", default="kms_keys.csv", type=str, help="File to write KMS keys to")
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

# Create a list object to hold the KMS Keys in each account:
kms_list_of_values = [] # List to hold the list of values for each row in the customized KMS output
total_key_count = 0 # Counter to hold the total number of KMS Keys identified
key_count_account = 0 # Counter to hold the number of KMS Keys identified in each account
key_count_dict = {} # Dict to hold the number of KMS Keys per account
# key_count_region (instantiated in each loop) holds the number of KMS Keys identified in the current region in each account

# Capture KMS keys for the current account: 

key_count_account = 0
for region in regions:
    if args.verbose: print(f"Identifying KMS Keys within account {current_account_id}, region {region}...")
    kms = boto3.client('kms', region_name=region)
    kms_response = kms.list_keys()
    if kms_response['Keys']:
        for key in kms_response['Keys']:
            describe = kms.describe_key(KeyId=key['KeyArn'])
            kms_row_list = [current_account_id, region, key['KeyId'], key['KeyArn'], describe['KeyMetadata']['KeyManager']]
            kms_list_of_values.append(kms_row_list)
        key_count_region = len(kms_response['Keys'])
        key_count_account += key_count_region
        if args.verbose: print(f"Identified {key_count_region} KMS keys in account {current_account_id} region {region}.")
total_key_count += key_count_account
key_count_dict[current_account_id] = key_count_account
if args.verbose: print(f"Identified {key_count_account} KMS Keys in account {current_account_id}.")

if args.verbose: print("Completed identification of KMS keys in the current account")

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

        # Iterate through account Ids and regions, capturing KMS Keys
        for account_id in account_ids:
            if account_id is not current_account_id:
                key_count_account = 0 # Reset KMS Keys per-account counter
                if args.verbose: print(f"Assuming role {args.assumed_role} in account {account_id}...")
                try:
                    # Assume role_name in each account and get temporary credentials (can use OrganizationAccountAccessRole but it is admin-level, advised to create/utilize read-only roles for this purposes)
                    sts_client = boto3.client('sts')
                    sts_response = sts_client.assume_role(RoleArn=f"arn:aws:iam::{account_id}:role/{args.assumed_role}", RoleSessionName="ListKMSInventoryScript")
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
                    # Capture KMS Keys for the current account in each region iteratively, and append to the list
                    account_ids_scanned.append(account_id)
                    for region in regions:
                        if args.verbose: print(f"Identifying KMS Keys within account {account_id}, region {region}...")
                        kms = assumed_session.client('kms', region_name=region)
                        kms_response = kms.list_keys()
                        if kms_response['Keys']:
                            for key in kms_response['Keys']:
                                describe = kms.describe_key(KeyId=key['KeyArn'])
                                kms_row_list = [account_id, region, key['KeyId'], key['KeyArn'], describe['KeyMetadata']['KeyManager']]
                                kms_list_of_values.append(kms_row_list)
                            key_count_region = len(kms_response['Keys'])
                            key_count_account += key_count_region
                            if args.verbose: print(f"Identified {key_count_region} KMS Keysin account {account_id} region {region}.")
                total_key_count += key_count_account
                key_count_dict[account_id] = key_count_account

kms_headers = [
    'Account_ID',
    'Region',
    'Key ID',
    'Key ARN',
    'Key Manager'
]

# Write KMS Keys to csv file
with open(args.file, 'w', newline="") as kmscsvfile:
    writer = csv.writer(kmscsvfile)
    writer.writerow(kms_headers)
    if args.verbose: print(kms_headers)
    for row in kms_list_of_values:
        writer.writerow(row)
        if args.verbose: print(row)

print("----------------------------------------")
print("AWS KMS key inventory is complete")
print(f"{total_key_count} KMS Keys were identified in {sum(value != 0 for value in key_count_dict.values())} accounts")
print(f"The following {len(account_ids_scanned)} accounts and regions were scanned: ")

print("Accounts:")
print(account_ids_scanned)
print("Regions:")
print(regions)

if args.verbose: 
    print("Number of KMS Keys identified in each account:")
    print(key_count_dict)

if error_list:
    with open("errors.txt", "w") as error_file:
        for error in error_list:
            error_file.write(f"\n{error}")
    print(f"The following {len(account_ids_failed)} accounts encountered errors:")
    print(account_ids_failed)
    print(f"{len(error_list)} errors occurred. Error messages are located at: {os.getcwd()}/errors.txt")

print(f"CSV output is saved at: {os.getcwd()}/{args.file}")
