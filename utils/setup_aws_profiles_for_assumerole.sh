#!/usr/bin/env bash
# set -e
#
# Retrieve all Member accounts from AWS Organizations and setup the credentials file to assumeRole
##############################################################################################################

# Argv should be the base profile name
profile=$1
target_role=$2
# target_role="cm_secops_role"
aws_default_region="us-east-1"

#######################################
# Print usage
# Globals:
#   profile
# Arguments:
#   None
# Returns:
#   None
#######################################
function usage() {
    echo "Usage: $0 <profile> <target_role>"
    exit 1
}

#######################################
# Get current account ID
# Globals:
#   profile
# Arguments:
#   None
# Returns:
#   AWS Current Account ID
#######################################
function id_current_account() {
    aws sts get-caller-identity --profile $profile --region $aws_default_region | jq -r '.Account'
}

#######################################
# Get all account IDs
# Globals:
#   profile
# Arguments:
#   None
# Returns:
#   AWS Account IDs List
#######################################
function get_all_account_ids() {
    aws organizations list-accounts --profile $profile --region $aws_default_region --query 'Accounts[?Status==`ACTIVE`].[Id]' --output text
}

#######################################
# Get all regions
# Globals:
#   none
# Arguments:
#   1. AWS Account ID
# Returns:
#   AWS Regions List
#######################################
function configure_profile() {
    aws configure --profile ${1} set role_arn arn:aws:iam::${1}:role/${target_role}
    aws configure --profile ${1} set source_profile ${profile}
}

if [ -z "$profile" ]; then
    usage
fi

if [ -z "$target_role" ]; then
    usage
fi

all_accounts=$(get_all_account_ids)
current_account=$(id_current_account)
for account_id in $all_accounts; do
    echo -e "\t\tSetting up role profile for account: $account_id"
    configure_profile $account_id
    echo -e "\t\t\t\t\t\t\t\t-done."
done
