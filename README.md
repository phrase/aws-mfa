# aws-mfa

Wrapper for awscli tool to support mfa tokens and also yubikeys.

## Requirements

* awscli (e.g. via `pip install awscli`)
* yubioauth (if you want to use the automatic-yubioauth feature)

## How it works

The wrapper makes sure you are always using aws credentials with a valid session tokens and automatically refreshes those after 6 hours by default (you can overwrite it with e.g. `"aws_duration":"12h"`).

## IAM policy

Here is the IAM policy we use for our `admin` accounts, the only actions accessible without a valid MFA token are `iam:GetUser` (to get information about the current user) and `iam:ListMFADevices` to allow listing the users MFA devices.

	{
			"Version": "2012-10-17",
			"Statement": [
					{
							"Effect": "Allow",
							"Action": "*",
							"Resource": "*",
							"Condition": {
									"NumericLessThan": {
											"aws:MultiFactorAuthAge": "21600"
									}
							}
					},
					{
							"Effect": "Allow",
							"Action": [
									"iam:GetUser",
									"iam:ListMFADevices"
							],
							"Resource": "*"
					}
			]
	}

## Configuration

	# $HOME/.config/aws.phraseapp.json
	{
		"aws_access_key_id": "key",
		"aws_secret_access_key": "secret",
		"aws_default_region": "eu-west-1",
		"aws_yubikey": "AWS PhraseApp"     // just needed if you want use a yubikey
	}

	export AWS_CREDENTIALS_PATH=$HOME/.config/aws.phraseapp.json
	aws-mfa iam get-user

	# or just use an alias like this if you want to make it work with multiple accounts
	alias aws-phraseapp='AWS_CREDENTIALS_PATH=$HOME/.config/aws.phraseapp.json aws-mfa $@'


## Yubikey

If use a yubikey to store your MFA credentials you can add e.g. `aws_yubikey`: "AWS PhraseApp"` to your aws config (this requires that yubioauth is installed) with `AWS PhraseApp` being the name of the MFA sequence on your yubikey.

The MFA prompt should automatically detect inserted yubikeys and automatically continue. You could still just manually type your MFA token.
