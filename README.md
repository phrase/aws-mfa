# aws-mfa

Wrapper for awscli tool to support mfa tokens and also yubikeys.


## Usage

	# $HOME/.config/aws.privat.json
	{
		"aws_access_key_id": "key",
		"aws_secret_access_key": "secret",
		"aws_default_region": "eu-west-1"
	}

	export AWS_CREDENTIALS_PATH=$HOME/.config/aws.privat.json
	aws-mfa iam get-user

