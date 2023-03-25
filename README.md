# Deprecated!

As of March 2023, aws-saml-session is deprecated, please use [aws-saml-session-mfa](https://www.npmjs.com/package/aws-saml-session-mfa) instead.

# aws-saml-session

Create temporary AWS credentials using SAML provider.

## Installation

```
npm install -g aws-saml-session
```

## Configuration

Set the following environment variables:

- IDP_URL - Identity Provider login URL,
- IDP_USER - IDP username,
- IDP_PASS - IDP password,
- AWS_PROFILE - `aws-cli` profile name.

## Usage

```
aws-saml-session
```
