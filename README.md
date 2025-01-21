# kms_cleanse
Explore and Clean up KMS Usage

This project is meant to audit KMS keys in use. Specifically we want to call attention to risky KMS behavior and implement guardrails to limit those behaviors.

Initially, this project will:
- enumerate active accounts
- enumerate s3 buckets
- enumerate s3 keys for buckets
- validate key is in account
- report failures to console

There will also be attempts to enforce the rules being enumerated.

## Assets

```
.
├── cloudformation
├── .editorconfig
├── .github
│   └── workflows
│       ├── lint_on_pull_request.yaml
│       └── lint_on_push.yaml
├── .gitignore
├── modules
└── README.md
```