# aws-kms-pkcs11

This repository contains a PKCS#11 implementation that uses AWS KMS as its backend. This allows you to bridge software that requires PKCS#11 plugins (like codesigning or certificate management software) with AWS KMS for key storage and management.

This implementation is not meant to be complete; it only implements enough of the PKCS#11 interface to enable signing with keys previously created in KMS. Functionality such as creating new keys and listing keys is not supported (you must set the key ID you want to use explicitly as noted in the configuration section below).

## Example

```bash
~$ ssh-add -s /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so 
Enter passphrase for PKCS#11: # Just press enter; no password is used
Card added: /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
~$ ssh-add -L
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLJqRBbRtYDvgNjK5xK1IcBaahVzbOyZULDjNpQ4VrWfmwthtIm4VEQLINherX8qx2hLaabvUfr7WLC5LDuyX6Q= arn:aws:kms:us-east-1:481384579625:key/dbafb7de-106e-4277-97fe-a7f5635516a5
~$ ssh-add -L >> ~/.ssh/authorized_keys
~$ ssh localhost
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-65-generic x86_64)

Last login: Thu Nov 19 10:35:42 2020
~$
```

## Configuration

AWS credentials are pulled from the usual places (environment variables, ~/.aws/credentials, and IMDS). Further configuration is read from either `/etc/aws-kms-pkcs11/config.json` or `$XDG_CONFIG_HOME/aws-kms-pkcs11/config.json` (note that `XDG_CONFIG_HOME=$HOME/.config` by default).

The following are options that can be set in `config.json`:

| Key | Required | Example | Explanation |
| --- | --- | --- | --- |
| kms\_key\_id | Y | dbafb7de-106e-4277-97fe-a7f5635516a5 | The KMS key id to use. (This plugin does not support any sort of key listing, auto-discovery, or creation of keys.) |
| aws\_region | N | us-west-2 | The AWS region where the above key resides. Uses us-east-1 by default. |

