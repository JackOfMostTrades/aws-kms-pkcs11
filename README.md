# aws-kms-pkcs11

This repository contains a PKCS#11 implementation that uses AWS KMS as its backend. This allows you to bridge software that requires PKCS#11 plugins (like codesigning or certificate management software) with AWS KMS for key storage and management.

This implementation is not meant to be complete; it only implements enough of the PKCS#11 interface to enable signing with keys previously created in KMS. Functionality such as creating new keys and listing keys is not supported (you must set the key ID you want to use explicitly as noted in the configuration section below).

# Examples

## PKCS#11 URIs

This module exposes KMS keys under a single token and slot. You can configure the module to expose all your KMS keys, a select few, or even just one; see the configuration section below. If you are exposing more than one key, and your PKCS#11 consumer supports it, you can use PKCS#11 URIs to specify the key ID that you want to use. For example:

```
export PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
openssl pkeyutl -engine pkcs11 -sign -inkey pkcs11:token=my-signing-key -keyform engine -out foo.sig -in foo
```

The token label used in the URI should match the label used in the configuration (see below). If you have not specified a label then the first 32 characters of the key's ID will be used as the label.

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
OpenSSL> pkeyutl -engine pkcs11 -sign -inkey pkcs11:token=my-signing-key -keyform engine -out foo.sig -in foo
engine "pkcs11" set.
PKCS#11: Initializing the engine
AWS_KMS: Debug enabled.
AWS_KMS: Attempting to load config from path: /home/ihaken/.config/aws-kms-pkcs11/config.json
AWS_KMS: Configured slots:
AWS_KMS:   dbafb7de-106e-4277-97fe-a7f5635516a5
Found 1 slot
Loading private key "pkcs11:token=my-signing-key"
Looking in slot -1 for key: 
[0]                            no pin            (my-signing-key)
Found slot:  
Found token: my-signing-key
AWS_KMS: Getting public key for key dbafb7de-106e-4277-97fe-a7f5635516a5
AWS_KMS: Successfully fetched public key data.
Found 1 private key:
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

$ PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so openssl req -config <(echo "$CONFIG") -x509 -key pkcs11:token=my-signing-key -keyform engine -engine pkcs11 -out mycert.pem -subj '/CN=mycert' -days 366 -addext basicConstraints=critical,CA:FALSE
```

## Windows code signing

Using [osslsigncode](https://github.com/mtrojnar/osslsigncode):

```bash
osslsigncode sign -h sha256 \
    -pkcs11engine /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so \
    -pkcs11module /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so \
    -certs mycert.pem -key 'pkcs11:token=my-signing-key' -in ~/foo.exe -out ~/foo-signed.exe
```

## Signing RAUC bundles

Since [RAUC](https://github.com/rauc/rauc) supports PKCS#11 keys, you can use your KMS key to sign RAUC bundles.

```bash
RAUC_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so rauc bundle --cert=mycert.pem --key='pkcs11:token=my-signing-key' input_dir/ my_bundle.raucb
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

If you do not create any configuration, the module will list all KMS keys and make them available as "tokens" in the provider. The label on each token will be the first 32 characters of the key's ID. All requests will use the default AWS region.

The following is an example configuration file:

```
{
  "slots": [
    {
      "label": "my-signing-key",
      "kms_key_id": "dbafb7de-106e-4277-97fe-a7f5635516a5",
      "aws_region": "us-east-1"
    }
  ]
}
```

The `slots` key is the only supported top-level attribute at the moment. This is a list of slot objects. The following keys are supported on each slot:

| Key | Required | Example | Explanation |
| --- | --- | --- | --- |
| kms\_key\_id | Y | dbafb7de-106e-4277-97fe-a7f5635516a5 | The key id to use for this slot. |
| label | N | my-signing-key | The token label to use for this slot; this is usually used when using a PKCS#11 URI. If not specified, the first 32 characters of the KMS key ID will be used as a label. |
| aws\_region | N | us-west-2 | The AWS region where the above key resides. Uses the AWS default if not specified. |

If you are encountering errors using this provider, try setting the `AWS_KMS_PKCS11_DEBUG` environment variable to a non-empty value. This should enable debug logging to stdout from the module.

# Installation

The easiest way to install the provider is to download the binary artifact from the GitHub releases page on this repository. Copy the `.so` to your pkcs11 directory (e.g. `/usr/lib/x86_64-linux-gnu/pkcs11`) and make sure to set it `chmod +x`. You should then create a config file as described above.

# Building from source

The Makefile in this repo assumes that you have built the AWS SDK with static libraries and installed it to `~/aws-sdk-cpp`. If so, then just running `make` should be sufficient. Check out the [circleci config](.circleci/config.yml) for pointers.

