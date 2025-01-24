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

def is_s3_bucket_key_enabled(account_id, region, bucket):
    '''
    Check if S3 Bucket Key is enabled for a given bucket.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name
        bucket (str): S3 bucket name

    Returns:
        bool: True if S3 Bucket Key is enabled, False otherwise.
    '''
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    s3_client = boto3.client('s3')

    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket)
        rules = response['ServerSideEncryptionConfiguration']['Rules']
        for rule in rules:
            if rule.get('BucketKeyEnabled') is True:
                return True
    except s3_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        logger.error("Error retrieving bucket encryption settings: %s", e)
        raise

    return False

def check_account_public_access_block(account_id, region="us-east-1"):
    """
    Check if "Block Public Access" settings are enabled for the entire account in S3.

    Args:
        account_id (str): AWS Account ID

    Returns:
        bool: True if public access is blocked, False otherwise.
    """
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    s3control_client = boto3.client('s3control')

    try:
        # Get the account-level public access block configuration
        response = s3control_client.get_public_access_block(AccountId=account_id)
        settings = response.get('PublicAccessBlockConfiguration', {})

        # Check if all public access block settings are enabled
        block_public_acls = settings.get('BlockPublicAcls', False)
        ignore_public_acls = settings.get('IgnorePublicAcls', False)
        block_public_policy = settings.get('BlockPublicPolicy', False)
        restrict_public_buckets = settings.get('RestrictPublicBuckets', False)

        all_settings_enabled = all([
            block_public_acls,
            ignore_public_acls,
            block_public_policy,
            restrict_public_buckets
        ])

        if not all_settings_enabled:
            logger.info("Account %s Public Access Block Settings:", account_id)
            logger.info("        %s BlockPublicAcls: %s", account_id, block_public_acls)
            logger.info("        %s IgnorePublicAcls: %s", account_id, ignore_public_acls)
            logger.info("        %s BlockPublicPolicy: %s", account_id, block_public_policy)
            logger.info("        %s RestrictPublicBuckets: %s", account_id, restrict_public_buckets)

        return all_settings_enabled

    except s3control_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        logger.debug("         %s No Public Access Block configuration found for this account.", account_id)
        return False
    except Exception as e:
        logger.error("Error checking public access block for account %s: %s", account_id, e)
        raise

def check_bucket_public_access_status(account_id, region, bucket_name):
    """
    Check "Public Access" status for a specific S3 bucket.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name
        bucket_name (str): S3 bucket name

    Returns:
        dict: A dictionary containing the public access settings for the bucket.
    """
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    s3_client = boto3.client('s3')

    try:
        # Get the bucket-level public access block configuration
        response = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        policy_status = response.get('PolicyStatus', {}).get('IsPublic', False)

        # Return the public access status
        return policy_status

    except s3_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            logger.debug("exception: %s, %s", bucket_name, e)
            return "no_policy"
        logger.error("Error checking public access block for bucket %s: %s", bucket_name, e)
        raise

def get_bucket_public_access_settings(account_id, region, bucket_name):
    """
    Query the individual block public access settings for an S3 bucket and return settings that are False.

    Args:
        account_id (str): AWS Account ID
        region (str): AWS region name
        bucket_name (str): S3 bucket name

    Returns:
        dict: A dictionary containing public access settings that are False.
    """
    # Initialize boto session
    boto3.setup_default_session(profile_name=account_id, region_name=region)
    s3_client = boto3.client('s3')

    try:
        # Get the bucket-level public access block configuration
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        settings = response.get('PublicAccessBlockConfiguration', {})
        block_public_acls = settings.get('BlockPublicAcls', False)
        ignore_public_acls = settings.get('IgnorePublicAcls', False)
        block_public_policy = settings.get('BlockPublicPolicy', False)
        restrict_public_buckets = settings.get('RestrictPublicBuckets', False)

        # log the results
        logger.debug("Bucket %s Public Access Block Settings:", bucket_name)
        logger.debug(" func        %s BlockPublicAcls: %s", bucket_name, block_public_acls)
        logger.debug(" func       %s IgnorePublicAcls: %s", bucket_name, ignore_public_acls)
        logger.debug(" func       %s BlockPublicPolicy: %s", bucket_name, block_public_policy)
        logger.debug(" func       %s RestrictPublicBuckets: %s", bucket_name, restrict_public_buckets)

        # Return the public access settings that are False
        return {
            'BlockPublicAcls': block_public_acls,
            'IgnorePublicAcls': ignore_public_acls,
            'BlockPublicPolicy': block_public_policy,
            'RestrictPublicBuckets': restrict_public_buckets
        }

    except s3_client.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchPublicAccessBlockConfiguration':
            logger.debug("Bucket %s does not have a public access block configuration.", bucket_name)
            return {}
        logger.error("Error retrieving public access settings for bucket %s: %s", bucket_name, e)
        raise
