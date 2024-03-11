# Import the boto3 library to utilize the AWS Python SDK, and botocore exceptions for error handling
import boto3
from botocore.exceptions import ClientError
import json
import argparse
import os

# Add command-line arguments for region and role to assume within accounts
parser = argparse.ArgumentParser(description="Get Security Groups Cross-Account Python Script - Arguments")
parser.add_argument("-r", "--region", default="us-east-1", type=str, help="AWS Region")
parser.add_argument("-o", "--organization", action="store_true", help="If specified, execute across all accounts in AWS Organization")
parser.add_argument("-a", "--assumed-role", default="ReadOnlyRole", type=str, help="Role to assume in each organization account")
parser.add_argument("-f", "--file", default="security_groups.json", type=str, help="File to write security groups to")
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

# Create a list object to hold the describe security group responses in each account:
security_groups_list = [] # List to hold the describe security group responses
total_sg_count = 0 # Counter to hold the total number of security groups identified
sg_count_account = 0 # Counter to hold the number of security groups identified in each account
sg_count_dict = {} # Dict to hold the number of security groups per account
# sg_count_region holds the number of security groups identified in the current region in each account

# Capture Security Groups for the current account:
sg_count_account = 0
for region in regions:
    if args.verbose: print(f"Identifying Security Groups within account {current_account_id}, region {region}...")
    ec2_client = boto3.client('ec2', region_name=region)
    describe_security_groups_response = ec2_client.describe_security_groups()
    security_groups_list.append(describe_security_groups_response)
    sg_count_region = len(describe_security_groups_response['SecurityGroups'])
    sg_count_account += sg_count_region
    if args.verbose: print(f"Identified {sg_count_region} security groups in account {current_account_id} region {region}.")
total_sg_count += sg_count_account
sg_count_dict[current_account_id] = sg_count_account

if args.verbose: print("Completed identification of Security Groups in the current account")

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
        
        # Iterate through account Ids and regions
        for account_id in account_ids:
            if account_id is not current_account_id:
                sg_count_account = 0 # Reset SG per-account counter
                # Assume role_name in each account and get temporary credentials (can use OrganizationAccountAccessRole but it is admin-level, advised to create/utilize read-only roles for this purposes)
                if args.verbose: print(f"Assuming role {args.assumed_role} in account {account_id}...")

                sts_client = boto3.client('sts')
                try:
                    sts_response = sts_client.assume_role(RoleArn=f"arn:aws:iam::{account_id}:role/{args.assumed_role}", RoleSessionName="ListResourcesScript")
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
                    # Capture security group details in each region iteratively, and append to the list
                    account_ids_scanned.append(account_id)
                    for region in regions:
                        if args.verbose: print(f"Role {args.assumed_role} assumed successfully in account {account_id}")
                        ec2_client = assumed_session.client('ec2', region_name=region)
                        describe_security_groups_response = ec2_client.describe_security_groups()
                        if describe_security_groups_response['SecurityGroups']:
                            security_groups_list.append(describe_security_groups_response)
                            sg_count_region = len(describe_security_groups_response['SecurityGroups'])
                            sg_count_account += sg_count_region
                            if args.verbose: print(f"Identified {len(describe_security_groups_response['SecurityGroups'])} security groups in account {account_id} region {region}.")
                        else:
                            if args.verbose: print(f"No security groups found in account {account_id} region {region}.")
                total_sg_count += sg_count_account
                sg_count_dict[account_id] = sg_count_account

# Write security groups to file
with open(args.file, 'w') as sgfile:
    sgfile.write(json.dumps(security_groups_list))

print("----------------------------------------")
print("AWS security group identification is complete")
print(f"{total_sg_count} security groups were identified in {len(security_groups_list)} account/region combinations.")
print(f"The following accounts and regions were scanned: ")

print("Accounts:")
print(account_ids_scanned)
print("Regions:")
print(regions)

if args.verbose:
    print("Number of security groups identified in each account: ")
    print(sg_count_dict)

if error_list:
    with open("errors.txt", "w") as error_file:
        for error in error_list:
            error_file.write(f"\n{error}")
    print(f"The following accounts encountered errors:")
    print(account_ids_failed)
    print(f"{len(error_list)} errors occurred. Error messages are located at: {os.getcwd()}/errors.txt")

print(f"JSON output is saved at: {os.getcwd()}/{args.file}")