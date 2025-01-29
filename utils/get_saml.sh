#!/usr/bin/env bash
# set -x
#
# This script will get a SAML token from a file and set it via AWS CLI
#
####################################################################################################

#######################################
# Print usage
# Globals:
#   None
# Arguments:
#   profile
# Returns:
#   None
#######################################
function usage() {
    echo "Usage: $0 <target_profile>"
    exit 1
}

#######################################
# Validate credential file exists where expected
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
function validate_credential_file() {
    if [ ! -f ~/Downloads/credentials.txt ]; then
        echo "SAML file not found. Please download from AWS SSO and try again."
        exit 1
    else
        echo "SAML file found."
        # Add a trailing newline to the file to allow the last line to be read
        echo "" >> ~/Downloads/credentials.txt
    fi
}

#######################################
# Get account ID from credentials file
# Globals:
#   None
# Arguments:
#   1. Profile
# Returns:
#   Account ID
#######################################
function get_account_id {
    aws sts get-caller-identity --profile $1 --region $aws_default_region | jq -r '.Account'
}

#######################################
# Get SAML token from file
# Globals:
#   target_profile
# Arguments:
#   None
# Returns:
#   SAML token
#######################################
function set_profiles() {
    while IFS= read -r line; do
        if [[ $line == *"aws_access_key_id"* ]]; then
            key=$(echo $line | cut -d'=' -f2)
            aws configure set aws_access_key_id $key --profile $target_profile
        elif [[ $line == *"aws_secret_access_key"* ]]; then
            value=$(echo $line | cut -d'=' -f2)
            aws configure set aws_secret_access_key $value --profile $target_profile
        elif [[ $line == *"aws_session_token"* ]]; then
            token=$(echo $line | cut -d'=' -f2)
            aws configure set aws_session_token $token --profile $target_profile
        fi
    done < ~/Downloads/credentials.txt
    bonus_profile=`get_account_id $target_profile`
    aws configure set aws_access_key_id $key --profile $bonus_profile
    aws configure set aws_secret_access_key $value --profile $bonus_profile
    aws configure set aws_session_token $token --profile $bonus_profile
}

#######################################
# Check Access with both profiles
# Globals:
#   None
# Arguments:
#   1. target_profile
#   2. bonus_profile
# Returns:
#   STS output
#######################################
function check_access() {
    echo "Checking access with $1 profile"
    aws sts get-caller-identity --profile $1 --region $aws_default_region 
    echo "Checking access with $2 profile"
    aws sts get-caller-identity --profile $2 --region $aws_default_region 
}

#######################################
# Main
#######################################
if [ $# -ne 1 ]; then
    target_profile="saml"
else
    target_profile=$1
fi

aws_default_region="us-east-1"
validate_credential_file
set_profiles
check_access $target_profile $bonus_profile
