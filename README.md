# aws-kms-pkcs11

This repository contains a PKCS#11 implementation that uses AWS KMS as its backend. This allows you to bridge software that requires PKCS#11 plugins (like codesigning or certificate management software) with AWS KMS for key storage and management.

This implementation is not meant to be complete; it only implements enough of the PKCS#11 interface to enable signing with keys previously created in KMS. Functionality such as creating new keys and listing keys is not supported (you must set the key ID you want to use explicitly as noted in the configuration section below).

# Examples

## PKCS#11 URIs

This module exposes KMS keys under a single token and slot. You can configure the module to expose all your KMS keys, a select few, or even just one; see the configuration section below. If you are exposing more than one key, and your PKCS#11 consumer supports it, you can use PKCS#11 URIs to specify the key ID that you want to use. For example:

```
export PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
openssl pkeyutl -engine pkcs11 -sign -inkey pkcs11:object=dbafb7de-106e-4277-97fe-a7f5635516a5 -keyform engine -out foo.sig -in foo
```

## Use with libp11 (aka libengine-pkcs11-openssl)

Note that this PKCS#11 provider allows for use of private keys without a "PIN". Previous versions of libp11 [did not allow](https://github.com/OpenSC/libp11/issues/242) the use of such keys. In particular, this version of libp11 is present in version of Ubuntu before focal, so make sure you are using libp11 >= 0.4.10.

You can do some simple verification of this module with the pkcs11 engine by following this example:

```
AWS_KMS_PKCS11_DEBUG=1 openssl
OpenSSL> engine pkcs11 -pre VERBOSE -pre MODULE_PATH:/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
(pkcs11) pkcs11 engine
[Success]: VERBOSE
[Success]: MODULE_PATH:/build/aws-kms-pkcs11/aws_kms_pkcs11.so
OpenSSL>
OpenSSL> pkeyutl -engine pkcs11 -sign -inkey pkcs11:object=dbafb7de-106e-4277-97fe-a7f5635516a5 -keyform engine -out foo.sig -in foo       
engine "pkcs11" set.
PKCS#11: Initializing the engine
AWS_KMS: Debug enabled.
AWS_KMS: Attempting to load config from path: /etc/aws-kms-pkcs11/config.json
AWS_KMS: Skipping config because we couldn't open the file.
AWS_KMS: Attempting to load config from path: /home/ihaken/.config/aws-kms-pkcs11/config.json
AWS_KMS: Configured to use AWS region: us-east-1
AWS_KMS: Configured KMS key ids:
AWS_KMS:   dbafb7de-106e-4277-97fe-a7f5635516a5
AWS_KMS:   7c9885bd-0832-47c1-86b7-d15631f545d5
Found 1 slot
Loading private key "pkcs11:object=dbafb7de-106e-4277-97fe-a7f5635516a5"
Looking in slot -1 for key: label=dbafb7de-106e-4277-97fe-a7f5635516a5
[0]                            no pin            (no label)
Found slot:  
Found token: 
AWS_KMS: Getting public key for key dbafb7de-106e-4277-97fe-a7f5635516a5
AWS_KMS: Successfully fetched public key data.
AWS_KMS: Getting public key for key ae38096a-62a3-4644-a112-4e803373cdb0
AWS_KMS: Got error from AWS fetching public key for key id ae38096a-62a3-4644-a112-4e803373cdb0: User: arn:aws:sts::867241597532:assumed-role/turtle_platform_security/ihaken@netflix.com is not authorized to perform: kms:GetPublicKey on resource: arn:aws:kms:us-east-1:867241597532:key/ae38096a-62a3-4644-a112-4e803373cdb0
Found 1 private key:
   1 P  id=64626166623764652d313036652d343237372d393766652d613766353633353531366135 label=dbafb7de-106e-4277-97fe-a7f5635516a5
AWS_KMS: Successfully called KMS to do a signing operation.
```

## Generate a self-signed certificate

This will create a self-signed certificate in `mycert.pem` using your KMS key.

```
$ CONFIG="
[req]                                                                           
distinguished_name=dn
[ dn ]
"

$ PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so openssl req -config <(echo "$CONFIG") -x509 -key pkcs11:object=dbafb7de-106e-4277-97fe-a7f5635516a5 -keyform engine -engine pkcs11 -out mycert.pem -subj '/CN=mycert' -days 366 -addext basicConstraints=critical,CA:FALSE
```

## Windows code signing

Using [osslsigncode](https://github.com/mtrojnar/osslsigncode):

```bash
osslsigncode sign -h sha256 \
    -pkcs11engine /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so \
    -pkcs11module /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so \
    -certs mycert.pem -key 'pkcs11:object=dbafb7de-106e-4277-97fe-a7f5635516a5' -in ~/foo.exe -out ~/foo-signed.exe
```

## Signing RAUC bundles

Since [RAUC](https://github.com/rauc/rauc) supports PKCS#11 keys, you can use your KMS key to sign RAUC bundles.

```bash
RAUC_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so rauc bundle --cert=mycert.pem --key='pkcs11:object=dbafb7de-106e-4277-97fe-a7f5635516a5' input_dir/ my_bundle.raucb
```

## SSH

I'm not really sure why you'd want to do this, but you can!

```bash
~$ ssh-add -s /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so 
Enter passphrase for PKCS#11: # Just press enter; no password is used
Card added: /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
~$ ssh-add -L
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLJqRBbRtYDvgNjK5xK1IcBaahVzbOyZULDjNpQ4VrWfmwthtIm4VEQLINherX8qx2hLaabvUfr7WLC5LDuyX6Q= dbafb7de-106e-4277-97fe-a7f5635516a5
~$ ssh-add -L >> ~/.ssh/authorized_keys
~$ ssh localhost
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-65-generic x86_64)

Last login: Thu Nov 19 10:35:42 2020
~$
```

# Configuration

AWS credentials are pulled from the usual places (environment variables, ~/.aws/credentials, and IMDS). Further configuration is read from either `/etc/aws-kms-pkcs11/config.json` or `$XDG_CONFIG_HOME/aws-kms-pkcs11/config.json` (note that `XDG_CONFIG_HOME=$HOME/.config` by default).

The following are options that can be set in `config.json`:

| Key | Required | Example | Explanation |
| --- | --- | --- | --- |
| kms\_key\_ids | N | ["dbafb7de-106e-4277-97fe-a7f5635516a5",7c9885bd-0832-47c1-86b7-d15631f545d5"] | An array of key ids to make available via this provider. If not specified, an API call will be made during initialization to list all keys available in KMS. This is generally discouraged since most consumers of PKCS#11 modules will enumerate all keys which in turn requires making a call to AWS for every key to fetch its public key. |
| aws\_region | N | us-west-2 | The AWS region where the above key resides. Uses us-east-1 by default. |

If you are encountering errors using this provider, try setting the `AWS_KMS_PKCS11_DEBUG` environment variable to a non-empty value. This should enable debug logging to stdout from the module.

# Installation

The easiest way to install the provider is to download the binary artifact from the GitHub releases page on this repository. Copy the `.so` to your pkcs11 directory (e.g. `/usr/lib/x86_64-linux-gnu/pkcs11`) and make sure to set it `chmod +x`. You should then create a config file as described above.

# Building from source

The Makefile in this repo assumes that you have built the AWS SDK with static libraries and installed it to `~/aws-sdk-cpp`. If so, then just running `make` should be sufficient. Check out the [circleci config](.circleci/config.yml) for pointers.

