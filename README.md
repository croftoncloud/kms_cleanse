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
         012345678910 Bucket: amazon-connect-524527b1c7a8 has no bucket policy
         012345678910 Bucket: aws-athena-query-results-us-west-2-012345678910 has no bucket policy
         012345678910 Bucket: ca-dmv-cross-account-demo-bucket has no bucket policy
         012345678910 Bucket: cf-templates-15etdy32qig1a-us-west-2 has no bucket policy
         012345678910 Bucket: dmv-callback-funcs-code has no bucket policy
         012345678910 Bucket: dmv-nodejs-lambdas-test has no bucket policy
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
