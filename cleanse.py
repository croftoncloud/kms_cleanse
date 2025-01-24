'''
This script will hunt down all KMS usage to ensure it meets secure standards.
/cleanse.py
'''
import argparse
import logging
from modules.config_loader import load_config
from modules.aws import get_aws_account_id, is_management_account, get_active_member_accounts, get_s3_buckets_and_regions, get_bucket_kms_key_arn, compare_account_id_with_kms_key, get_kms_key_arn_by_id, is_s3_bucket_key_enabled, check_account_public_access_block, check_bucket_public_access_status, get_bucket_public_access_settings

logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)
logger = logging.getLogger(__name__)
# Adjust logging for boto3 and botocore
logging.getLogger("botocore").setLevel(logging.WARNING)

def enumerate_buckets(accounts, region, keymatch=False, bucketkey=False, public_status=False, public_account=False, public_buckets=False):
    """
    For each account, enumerate the S3 bucket KMS key usage.

    Args:
        accounts (list): List of AWS account IDs
        region (str): AWS region name
        bucketkey (bool): Whether to check for bucket key encryption
        public (bool): Whether to check for public access settings

    Returns:
        None
    """
    for account in accounts:
        # Log the account ID
        logger.info("Account: %s", account)
        if public_account:
            # Check account level public access settings
            if not check_account_public_access_block(account):
                logger.info("Account: %s does not block public access", account)

        # if the only check being performed is public_account, then skip the bucket enumeration
        # if public_account and not (keymatch or bucketkey or public_status or public_buckets):
        #     continue
        buckets = get_s3_buckets_and_regions(account, region)
        for bucket_name, bucket_region in buckets.items():
            # If BucketKey check is requested, check if the bucket key is enabled
            if bucketkey:
                bucket_key_enabled = is_s3_bucket_key_enabled(account, bucket_region, bucket_name)
                if bucket_key_enabled:
                    logger.debug("Account: %s, Region: %s, Bucket: %s has bucket key enabled", account, bucket_region, bucket_name)
                    continue
                logger.info("Account: %s, Region: %s, Bucket: %s does not have bucket key enabled", account, bucket_region, bucket_name)

            # If Public Access check is requested, validate public access settings
            if public_status:
                # Check bucket level public access settings
                public_access_settings = check_bucket_public_access_status(account, bucket_region, bucket_name)
                if not public_access_settings:
                    logger.debug("         %s Bucket: %s is not currently publicly exposed according to AWS", account, bucket_name)
                elif public_access_settings == "no_policy":
                    logger.info("         %s Bucket: %s has no bucket policy", account, bucket_name)

            # If Public Access Block check is requested, validate public access block settings
            if public_buckets:
                # Check bucket level public access block settings
                logger.debug("         %s Bucket: %s", account, bucket_name)
                public_access_block_settings = get_bucket_public_access_settings(account, bucket_region, bucket_name)
                if not public_access_block_settings:
                    logger.info("         %s Bucket: %s does not have public access block settings enabled", account, bucket_name)
                else:
                    logger.debug("         %s Bucket: %s has public access block settings enabled", account, bucket_name)

            # KMS Key validation logic
            if keymatch:
                kms_key_arn = get_bucket_kms_key_arn(account, bucket_region, bucket_name)
                if kms_key_arn:
                    not_same_account = compare_account_id_with_kms_key(account, kms_key_arn)
                    if not not_same_account:
                        new_kms_arn = get_kms_key_arn_by_id(account, bucket_region, kms_key_arn)
                        if new_kms_arn:
                            logger.info("Account: %s, Region: %s, Bucket %s, KMS Key: %s resolves to %s", account, bucket_region, bucket_name, kms_key_arn, new_kms_arn)
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
    parser.add_argument("--keymatch", action="store_true", help="Check for KMS key account ID mismatch")
    parser.add_argument("--bucketkey", action="store_true", help="Check for S3 bucket key encryption")
    parser.add_argument("--public-status", action="store_true", help="Check the AWS Status for Bucket Public Access")
    parser.add_argument("--public-buckets", action="store_true", help="Check for Block Public Access on S3 buckets")
    parser.add_argument("--public-account", action="store_true", help="Check for Block Public Access for the AWS account")
    args = parser.parse_args()

    # Load configuration from config.yaml
    logger.info("Loading configuration...")
    config = load_config()

    # Ensure mandatory parameters are provided
    aws_profile = args.profile or config.get('aws', {}).get('account_id')
    if not aws_profile:
        logger.error("AWS profile name not provided.")
        return
    aws_region = args.region or config.get('aws', {}).get('default_region')
    if not aws_region:
        logger.error("AWS region not provided.")
        return

    if args.profile:
        config['aws']['account_id'] = args.profile

    logger.info("Starting KMS cleanse for profile: %s, region: %s", aws_profile, aws_region)

    accounts = determine_account_scope(config)
    logger.info("Enumerating buckets in accounts %s", accounts)
    logger.info("Only non-compliant buckets will be displayed.")
    if args.keymatch:
        logger.info("KMS Key account ID mismatch check is enabled.")
    if args.bucketkey:
        logger.info("Bucket Key check is enabled.")
    if args.public_status:
        logger.info("Bucket Public Access Status check is enabled.")
    if args.public_buckets:
        logger.info("Bucket Public Access Block check is enabled.")
    if args.public_account:
        logger.info("Account Public Access Block check is enabled.")
    # pad the output with an extra line
    logger.info("")

    # Run the specified checks based on flags
    enumerate_buckets(accounts, aws_region, keymatch=args.keymatch, bucketkey=args.bucketkey, public_status=args.public_status, public_account=args.public_account, public_buckets=args.public_buckets)

if __name__ == "__main__":
    main()
