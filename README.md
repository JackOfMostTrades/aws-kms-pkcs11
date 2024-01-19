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

If you have downloaded the public key from KMS to `my-signing-key.pub` you can verify the above signature with

```
openssl pkeyutl -in foo -verify -sigfile foo.sig -inkey my-signing-key.pub  -pubin
Signature Verified Successfully
```

This example using `pkeyutl` assumes you are using an EC key.
If you are using an RSA key, append the `-pkeyopt digest:sha256` option to both the sign and verify steps. 

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

## P11Tool Configuration

p11tool is a useful tool included as part of the gnutls-bin package on Debian-based systems. It can be installed with `apt install gnutls-bin`. After it is installed you can configure it to be aware of the aws-kms-pkcss11 module as follows:

```
mkdir -p "/etc/pkcs11/modules"
touch "/etc/pkcs11/pkcs11.conf"
cat >"/etc/pkcs11/modules/aws-kms-pkcs11.module" <<EOF
module: /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
critical: no
EOF
```

After this configuration you can use the p11tool command to list some helpful info

```
p11tool --list-tokens
p11tool --list-token-urls
```

## Kernel Module Signing

An example for kernel module signing [can be found here](kernel_signing.md).

## GPG Signing

An example for GPG signing [can be found here](gpg_signing.md).

## pesign

pesign is used by most Linux distributions to sign PE binaries for secure boot

It uses the NSS libraries which relies on a "certdb" database with the certificates, and the configuration of the PKCS11 modules. In this example, we'll create a custom certdb for signing, and add our module to it:

```
mkdir my-cert-db
certutil -N --empty-password -d my-cert-db
modutil -dbdir my-cert-db -add kms -libfile /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
```

You can check that the key and certificate are there:
```
certutil -d my-cert-db -K -h all
certutil -d my-cert-db -L -h all
```

Now, assuming you have a key names "my-signing-key" configured with a certificate setup in your json file (as documented below), you can do:

```
pesign -i <input_file> -o <output_file> -s -n my-cert-db -c my-signing-key -t my-signing-key
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
      "aws_region": "us-east-1",
      "certificate_path": "/etc/aws-kms-pkcs11/cert.pem"
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
| certificate | N | MIIBMjCB2... | A base64-encoded DER-encoded X.509 certificate to make available as an object on this slot. This is useful for use-cases where a signing library expects both a certificate and key available on the PKCS#11 token. You can generate a certificate with this format with a command such as `openssl x509 -in mycert.pem -outform der \| openssl base64 -A` |
| certificate\_path | N | /etc/aws-kms-pkcs11/mycert.pem | Same as "certificate" but refers to a PEM certificate on disk instead of embedding the certificate value into the config. |
| certificate_arn | N |  arn:aws:acm-pca:us-west-2:123456789876:certificate-authority/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx/certificate/xxxxxxxxxxxxxxxxxxxx | Same as "certificate" but refers to a PEM certificate in ACM-PCA. |
| ca_arn | N |  arn:aws:acm-pca:us-west-2:123456789876:certificate-authority/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx | Optionally provide the ARN of the CA authority that owns the certificate specified in "certificate_arn". If unspecified, extracted from certificate_arn |

If you are encountering errors using this provider, try setting the `AWS_KMS_PKCS11_DEBUG` environment variable to a non-empty value. This should enable debug logging to stdout from the module.

# Installation

The easiest way to install the provider is to download the binary artifact from the GitHub releases page on this repository. Copy the `.so` to your pkcs11 directory (e.g. `/usr/lib/x86_64-linux-gnu/pkcs11`) and make sure to set it `chmod +x`. You should then create a config file as described above.

# Building from source

The Makefile in this repo tries to intuit the location of the various components and libraries it needs. This can be controlled by the following variables:

`AWS_SDK_PATH`       : Path to the AWS sdk  
`PKCS11_INC`         : Path to the pkcs11.h header file  
`JSON_C_INC`         : Path to the json-c library headers  

Additionally these variables can be set to control the use of the AWS SDK static vs. dynamic libraries. By default the Makefile will use
the static ones if available, otherwise the dynamic ones:

`AWS_SDK_STATIC = y`     : Force use of static libraries for both C and C++  
`AWS_SDK_STATIC = n`     : Force use of dynamic libraries for both C and C++  
`AWS_SDK_C_STATIC = y`   : Force use of static libraries for C  
`AWS_SDK_C_STATIC = n`   : Force use of dynamic libraries for C  
`AWS_SDK_CPP_STATIC = y` : Force use of static libraries for C++  
`AWS_SDK_CPP_STATIC = n` : Force use of dynamic libraries for C++  

The variable `PKCS11_MOD_PATH` can be used to control the destination directory for `make install`.

The variable `AWS_SDK_USE_SYSTEM_PROXY` can be set to `y` to cause aws-kms-pkcs11 to use the HTTP proxy server set in the `HTTPS_PROXY` environment variable. This defaults to `n`, meaning the proxy settings from the environment are ignored by default. See [AWS Command Line Interface - Use an HTTP proxy](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-proxy.html) and [aws-sdk-cpp#2679](https://github.com/aws/aws-sdk-cpp/pull/2679) for further details. Note that this option was, as of this writing, added relatively recently (September 2023) and the library may therefore not compile with `AWS_SDK_USE_SYSTEM_PROXY=y`.
