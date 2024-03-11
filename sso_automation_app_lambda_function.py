# Import the boto3 library to utilize the AWS Python SDK, and botocore exceptions for error handling
# Import json for returning the response
# Import os for getting environment variables
import boto3
from botocore.exceptions import ClientError
import json
import os

def lambda_handler(event, context):
    # Create empty response
    create_account_assignment_response = ""
    # Call the AWS SSO API to create an account permission set assignment, storing the response in "create_account_assignment_response"
    try:
        sso_client = boto3.client('sso-admin')
        create_account_assignment_response = sso_client.create_account_assignment(
            InstanceArn = os.environ['INSTANCE_ARN'], # SSO Instance ARN in which to create assignment
            PermissionSetArn = os.environ['PERMISSION_SET_ARN'], # ARN of permission set
            TargetType = 'AWS_ACCOUNT', # Entity type for assignment - AWS_ACCOUNT
            TargetId = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"], # AWS Account ID to create assignment for
            PrincipalType = 'GROUP', # Type of principal - USER | GROUP
            PrincipalId = os.environ['PRINCIPAL_ID'] # ID of group to assign permission set to
        )
    # Error handling, printing to screen and storing the response in "create_account_assignment_response"
    except ClientError as error:
        print(f"Couldn't complete account-permission set assignment. Here's the error: {error.response["Error"]["Message"]}")
        create_account_assignment_response = error.response["Error"]["Message"]
    # Return the response of the create_account_assignment action
    return {
        'statusCode': 200,
        'body': json.dumps(create_account_assignment_response)
    }