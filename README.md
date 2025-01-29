# kms_cleanse
Explore and Clean up KMS Usage

Initially, this project is meant to audit KMS keys in use. Specifically we want to call attention to risky KMS behavior and implement guardrails to limit those behaviors.

This project will:
- enumerate active accounts
- enumerate s3 buckets
- enumerate s3 keys for buckets
- validate key is in account
- report failures to console

## Usage

Basic arguments are all optional outside the profile. The configuration can be read in from config.yaml if the intent is to deploy this for a single account or organizations. Configuration example is available in the `config.example.yaml` file.

```
python3 ./cleanse.py --help
usage: cleanse.py [-h] [--profile PROFILE] [--region REGION] [--keymatch] [--bucketkey] [--public-status] [--public-buckets] [--public-account]

Hunt down all KMS usage to ensure it meets secure standards.

options:
  -h, --help         show this help message and exit
  --profile PROFILE  AWS profile name
  --region REGION
  --keymatch         Check for KMS key account ID mismatch
  --bucketkey        Check for S3 bucket key encryption
  --public-status    Check the AWS Status for Bucket Public Access
  --public-buckets   Check for Block Public Access on S3 buckets
  --public-account   Check for Block Public Access for the AWS account
  ```

Example scan:
```
python3 ./cleanse.py --profile saml --public-account --public-status --public-buckets --keymatch
Loading configuration...
Starting KMS cleanse for profile: saml, region: us-east-1
Determining account scope... saml, us-east-1
Determining account management status... saml, us-east-1
Standalone account detected. Returning its own account ID...
Enumerating buckets in accounts ['012345678910']
Only non-compliant buckets will be displayed.
KMS Key account ID mismatch check is enabled.
Bucket Public Access Status check is enabled.
Bucket Public Access Block check is enabled.
Account Public Access Block check is enabled.

Account: 012345678910
Account: 012345678910 does not block public access
         012345678910 Bucket: amazon-connect-012345678910 has no bucket policy
         012345678910 Bucket: aws-athena-query-results-us-west-2-012345678910 has no bucket policy
         012345678910 Bucket: 012345678910-account-demo-bucket has no bucket policy
         012345678910 Bucket: cf-templates-012345678910-us-west-2 has no bucket policy
         012345678910 Bucket: callback-funcs-code has no bucket policy
         012345678910 Bucket: misc-nodejs-lambdas-test has no bucket policy
```


## Assets

```
.
├── cleanse.py
├── cloudformation
├── config.example.yaml
├── .editorconfig
├── .github
│   └── workflows
│       ├── lint_on_pull_request.yaml
│       └── lint_on_push.yaml
├── .gitignore
├── modules
└── README.md
```

## Helper Utilities

There are some helper scripts that were authored in projects-past that need to be udpated to current standards, but they can be used as reference to get named profiles in place. These scripts were authored to work in Windows Subsystem for Linux (WSL 2.0) on an Ubuntu-based instance.

`get_saml.sh`

Pair with `SAML to AWS STS Keys Conversion` Chrome extension and set it to save as credentials.txt. This script will read the credentials and feed values to aws configure. It extracts the credential values and plugs them into AWS CLI commands:

```
aws set aws_access_key_id $key --profile saml
aws set aws_secret_access_key $value --profile saml
aws set aws_session_token $token --profile saml
```

Usage:

```
get_saml.sh
SAML file found.
Checking access with saml profile
{
    "UserId": "AROA3O25ZDFQMQ3Y5EW:wbrady@domain.tld",
    "Account": "012345678910",
    "Arn": "arn:aws:sts::012345678910:assumed-role/Okta-Administrator/wbrady@domain\.tld"
}
Checking access with 012345678910 profile
{
    "UserId": "AROA3O25ZDFQMQ3Y5EW:wbrady@domain\.tld",
    "Account": "012345678910",
    "Arn": "arn:aws:sts::012345678910:assumed-role/Okta-Administrator/wbrady@domain\.tld"
}
```

`setup_aws_profiles_for_assumerole.sh`

If you have a role or credential that you can use across all accounts in an Organization, this script will:

- Accept the named profile as input
- Connect to the account to query all active Organization Members
- Iterate through each account to setup a named profile with the role you specify

```
 ./setup_aws_profiles_for_assumerole.sh saml iv_secops_role
                Setting up role profile for account: 012345678910
                                                                -done.
                Setting up role profile for account: 123456789101
                                                                -done.
                Setting up role profile for account: 234567891011
                                                                -done.
```

`cfn-security-operations-role.yaml`

This CloudFormation template can be deployed to an Organization as a StackSet from the Management Account to provide a target role for the above command and many other security-related tools.

