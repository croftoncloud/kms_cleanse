'''
This script will hunt down all KMS usage to ensure it meets secure standards.
/cleanse.py
'''
import argparse
import logging
from modules.config_loader import load_config
from modules.aws import get_aws_account_id, is_management_account, get_active_member_accounts, get_s3_buckets_and_regions, get_bucket_kms_key_arn, compare_account_id_with_kms_key, get_kms_key_arn_by_id, is_s3_bucket_key_enabled

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Adjust logging for boto3 and botocore
logging.getLogger("botocore").setLevel(logging.WARNING)

def enumerate_buckets(accounts, region, bucketkey=False):
    """
    For each account, enumerate the S3 bucket KMS key usage.

    Args:
        accounts (list): List of AWS account IDs
        region (str): AWS region name

    Returns:
        None
    """
    for account in accounts:
        buckets = get_s3_buckets_and_regions(account, region)
        logger.info("Enumerating buckets in account %s", account)
        for bucket_name, bucket_region in buckets.items():
            # If Bucketkey check is requested, check if the bucket key is enabled
            if bucketkey:
                bucket_key_enabled = is_s3_bucket_key_enabled(account, bucket_region, bucket_name)
                if bucket_key_enabled:
                    # If bucket key is enabled, skip it.
                    logger.debug("Account: %s, Region: %s, Bucket: %s has bucket key enabled", account, bucket_region, bucket_name)
                    continue
                else:
                    logger.info("Account: %s, Region: %s, Bucket: %s does not have bucket key enabled", account, bucket_region, bucket_name)

            # Does it have a KMS key?
            kms_key_arn = get_bucket_kms_key_arn(account, bucket_region, bucket_name)
            # Is it a valid KMS key or does it need to be reviewed?
            if kms_key_arn:
                # Does the KMS Key belong to the account?
                # If yes, we do not need to log it. If no, then we need to look it up to be sure.
                not_same_account = compare_account_id_with_kms_key(account, kms_key_arn)
                if not not_same_account:
                    new_kms_arn = get_kms_key_arn_by_id(account, bucket_region, kms_key_arn)
                    if new_kms_arn:
                        logger.info("Account: %s, Region: %s, KMS Key: %s resolves to %s", account, bucket_region, kms_key_arn, new_kms_arn)
                    else:
                        logger.warning("Account: %s, Region: %s, KMS Key: %s does not exist in this account", account, bucket_region, kms_key_arn)

def determine_account_scope(config):
    """
    Determine the scope of accounts based on the current account type.

    Args:
        config (dict): Configuration dictionary

    Returns:
        list: List of AWS account IDs
    """
    account_id = config.get('aws', {}).get('account_id')
    region = config.get('aws', {}).get('default_region')

    logger.info("Determining account scope... %s, %s", account_id, region)

    if is_management_account(account_id, region):
        print("Management account detected. Listing active member accounts...")
        return get_active_member_accounts(account_id, region)
    print("Standalone account detected. Returning its own account ID...")
    return [get_aws_account_id(account_id, region)]

def main():
    '''
    Main function
    '''
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Hunt down all KMS usage to ensure it meets secure standards.")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--bucketkey", action="store_true", help="Check for S3 bucket key encryption")
    args = parser.parse_args()

    # Load configuration from config.yaml
    logger.info("Loading configuration...")
    config = load_config()

    # Ensure mandatory parameters are provided
    aws_profile = args.profile or config.get('aws', {}).get('account_id')
    if not aws_profile:
        logging.error("AWS profile name not provided.")
        return
    aws_region = args.region or config.get('aws', {}).get('default_region')
    if not aws_region:
        logging.error("AWS region not provided.")
        return
    logger.info("Starting KMS cleanse for profile: %s, region: %s", aws_profile, aws_region)

    accounts = determine_account_scope(config)
    logger.info("Enumerating buckets in accounts %s", accounts)
    # Enumerate S3 buckets and their KMS key usage. Include bucketkey check if requested.
    if args.bucketkey:
        enumerate_buckets(accounts, aws_region, bucketkey=True)
    else:
        enumerate_buckets(accounts, aws_region)

if __name__ == "__main__":
    main()
