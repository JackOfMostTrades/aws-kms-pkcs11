GPG Signing using AWS KMS
=========================

`gpg` can use the PKCS#11 provider by way of [gnupg-pkcs11-scd](https://github.com/alonbl/gnupg-pkcs11-scd).
Note that 0.10.0+ is required.

Configure `gpg-agent` to consult the smartcard daemon.
Keys must have corresponding certificates to be discovered by the daemon.
```
mkdir gpgtmp
export GNUPGHOME="${PWD}/gpgtmp"

# configure the agent
cat <<EOF >> "${GNUPGHOME}/gpg-agent.conf"
scdaemon-program /usr/bin/gnupg-pkcs11-scd
EOF

# configure the smartcard daemon
cat <<EOF >> "${GNUPGHOME}/gnupg-pkcs11-scd.conf"
providers kms
provider-kms-library /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
log-file /dev/null
EOF
```

The first import into `gpg` requires the keygrip and additional metadata.
```
# read keys from the card
gpg --card-status

# find the keygrip
KEYGRIP=$(find ${GNUPGHOME}/private-keys-*.d -type f -name '*.key' -printf '%P'|cut -d '.' -f1|head -n1)

# import signing key
# (toggle 'e' since encryption is not supported)
gpg --expert --full-generate-key --command-fd 0 <<EOF
13
${KEYGRIP}
e
q
0
my-signing-key


EOF

# export the key for subsequent use
gpg --output my-signing-key.gpg my-signing-key
```

Subsequent imports only need the exported key and the smartcard discovery step.
```
gpg --import my-signing-key.gpg
gpg --card-status
```


Common Issues
=============

The binary releases for `aws_kms_pkcs11.so` are built on Ubuntu (20.04 at the time of writing) and have a dynamic dependency on OpenSSL and libjson-c.
If you encounter issues using the binary release, you will likely need to rebuild `aws_kms_pkcs11` on your platform.

