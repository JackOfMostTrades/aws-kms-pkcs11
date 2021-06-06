Kernel Signing using AWS KMS
==============================

When building a custom kernel it may be useful to sign the modules to prevent unauthorized module loading on the system. This is most appropriate for embedded devices. The process is pretty straightforward.

At first we need to do a fake build to get a x509.genkey file which we can use for generating the certificate. A sample is included, but it's better to use the same one the kernel would use. The kernel will automatically generate this file and create a certificate if CONFIG_MODULE_SIG_KEY="", so we take advantage of this to get a sample x509.genkey file.

Add the following to the kernel config:
```
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_MODULE_SIG_KEY=""
```
Then build the kernel using `make` and the x509.genkey file should be located in `<kernel_source>/certs/x509.genkey`. You will use this file to self-sign a certificate in the following step.

If you want to skip the above step and use a passed file here is a sample. Some extra fields have been added (such as Organisation Name) to provide extra information in the certificate.
```
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
countryName            = US
stateOrProvinceName    = Your State
localityName           = Your City
organizationName       = Your Company
commonName             = Kernel Signing Key
emailAddress           = you@example.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

Make sure your aws-kms-pkcs11 json config is setup to point to the key, then sign your certificate with the following 
 `AWS_KMS_PKCS11_DEBUG=1 PKCS11_MODULE_PATH="/usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so" openssl req -config <(cat "<kernel_source>/certs/x509.genkey") -x509 -key "pkcs11:token=<your_key_label>" -keyform engine -engine pkcs11 -out mycert.pem -days 36500`. 
 
Now you have a signed certificate with "mycert.pem", add this as a certificate in your aws kms config, update with this line (more details in config section below): `"certificate_path": "mykey.crt"`.

Update your kernel config:
`CONFIG_MODULE_SIG_KEY="pkcs11:token=<your_key_label>`

Now make the kernel as normal and modules will be signed using the kms private key and your public certificate you just signed above.

Make sure to keep the self signed certificate in a safe place.
