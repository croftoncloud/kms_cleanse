'''
AWS Account functions
/modules/aws.py
'''
import logging
import boto3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Adjust logging for boto3 and botocore
logging.getLogger("botocore").setLevel(logging.WARNING)

def get_aws_account_id(account_id, region):
    '''
    Retrieve the AWS Account ID of the current session.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name

    Returns:
        str: AWS Account ID
    '''
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    # Retrieve the AWS Account ID of the current session.
    sts_client = boto3.client('sts')
    return sts_client.get_caller_identity()['Account']

def is_management_account(account_id, region):
    '''
    Check if the current AWS account is a management account in AWS Organizations.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name

    Returns:
        bool: True if the account is a management account, False otherwise
    '''
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    # Check if the current AWS account is a management account in AWS Organizations.

    logger.info("Determining account management status... %s, %s", account_id, region)

    try:
        org_client = boto3.client('organizations')
        response = org_client.describe_organization()
        return response['Organization']['MasterAccountId'] == get_aws_account_id(account_id, region)
    except org_client.exceptions.AWSOrganizationsNotInUseException:
        return False

def get_active_member_accounts(account_id, region):
    '''
    List all active member accounts in the AWS Organization.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name

    Returns:
        list: Active member account IDs
    '''
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    # List all active member accounts in the AWS Organization.
    org_client = boto3.client('organizations')
    paginator = org_client.get_paginator('list_accounts')
    active_accounts = []

    for page in paginator.paginate():
        for account in page['Accounts']:
            if account['Status'] == 'ACTIVE':
                active_accounts.append(account['Id'])

    return active_accounts

def get_s3_buckets_and_regions(account_id, region):
    '''
    Retrieve a dictionary of S3 bucket names and their associated regions.

    Returns:
        dict: A dictionary where the keys are bucket names and the values are their regions.
    '''
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    s3_client = boto3.client('s3')
    buckets = {}

    response = s3_client.list_buckets()
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
        # AWS returns None for the "us-east-1" region
        bucket_location = bucket_location or 'us-east-1'
        buckets[bucket_name] = bucket_location

    return buckets

def get_bucket_kms_key_arn(account_id, region, bucket):
    '''
    Retrieve the KMS Key ID for an S3 bucket.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name
        bucket (str): S3 bucket name

    Returns:
        str: KMS Key ID if implemented, or False otherwise.
    '''
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    s3_client = boto3.client('s3')

    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket)
        rules = response['ServerSideEncryptionConfiguration']['Rules']
        for rule in rules:
            if 'KMSMasterKeyID' in rule['ApplyServerSideEncryptionByDefault']:
                return rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']
    except s3_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        logger.error("Error retrieving bucket encryption: %s", e)
        raise

    return False

def compare_account_id_with_kms_key(account_id, kms_key_arn):
    '''
    Compare the account_id with the account string in the KMS key ARN.

    Args:
        account_id (str): AWS Account ID
        kms_key_arn (str): KMS key ARN

    Returns:
        bool: True if the account_id matches the account in the KMS key ARN, False otherwise.
    '''
    try:
        # Extract the account ID from the KMS key ARN
        arn_parts = kms_key_arn.split(':')
        if len(arn_parts) > 4:
            kms_account_id = arn_parts[4]
            return account_id == kms_account_id
    except IndexError as e:
        logger.error("Error parsing KMS key ARN: %s", e)
    except ValueError as e:
        logger.error("Error parsing KMS key ARN: %s", e)
    return False

def get_kms_key_arn_by_id(account_id, region, key_id):
    '''
    Query the KMS service for a key with the given key_id and return its ARN.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name
        key_id (str): KMS key ID to query

    Returns:
        str: The ARN of the KMS key if found, or "Key not found" otherwise.
    '''
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    kms_client = boto3.client('kms')

    logger.debug("Retrieving KMS key by ID: %s", key_id)

    try:
        paginator = kms_client.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page['Keys']:
                logger.debug("Key: %s", key)
                if key['KeyId'] == key_id:
                    key_metadata = kms_client.describe_key(KeyId=key['KeyId'])
                    logger.debug("Key metadata: %s", key_metadata)
                    return key_metadata['KeyMetadata']['Arn']
    except kms_client.exceptions.NotFoundException:
        logger.warning("Key ID %s not found.", key_id)
        return "Key not found"
    except kms_client.exceptions.ClientError as client_error:
        logger.error("ClientError while retrieving KMS key: %s", client_error)
        raise
    except boto3.exceptions.Boto3Error as boto_error:
        logger.error("Boto3 error occurred: %s", boto_error)
        raise

    logger.warning("No matching key found for ID: %s", key_id)
    return "Key not found"
