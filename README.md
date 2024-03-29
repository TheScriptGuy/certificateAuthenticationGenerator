# Generate Certificate files for testing purposes
This script is meant to help with the easy creation of a Root Certificate Authority as well as a certificate for client authentication.

Default values:
* The company name is assumed to be `ACME Corp`.
* The certificates are valid by default for `1 year`.
* Root CA uses `2048` bits.
* Root CA uses `sha512` digest.
* Client Authentication Certificate uses `2048` bits.
* Client Authentication Certificate uses `sha256` digest.

If `--ecc` argument is present, then the following applies:
* Root CA uses `secp256r1` encryption
* Root CA uses `sha512` digest
* Client Authentication certificate uses `secp256r1` encryption
* Client Authentication certificate uses `sha256` digest.

You can change the company name by using the `--companyName` argument.

# Requirements
pyopenssl must be installed. To install:
```bash
$ python3 -m pip install cryptography==40.0.2 datetime pyasn1 idna
```

# Help
```bash
$ python3 generate-certificate.py -h
usage: generate-certificate.py [-h] [--companyName COMPANYNAME] [--generateRootCA] [--generateClientCertificate] [--generatePKCS12]
                               [--nonRestrictiveRootCA] [--ecc] [--dnsName] [--userPrincipalName] [--removeAllCertsAndKeys] [--windowsInstallation]

Certificate Generation v1.10

options:
  -h, --help            show this help message and exit
  --companyName COMPANYNAME
                        Entity/Company name for the certificates.
  --generateRootCA      Generate the Root CA certificate and key. Uses --companyName in certificate creation.
  --generateClientCertificate
                        Generate the client certificate to use for client authentication.
  --generatePKCS12      generate a PKCS12 type file.
  --nonRestrictiveRootCA
                        Remove Root CA extensions. USE WITH CAUTION.
  --ecc                 Use Elliptic Curves in preference to RSA.
  --dnsName             Add a Subject Alternative Name (SAN) for the DNS hostname.
  --userPrincipalName   Add a Subject Alternative Name (SAN) for the Windows User Principal Name (UPN).
  --removeAllCertsAndKeys
                        Removes all files matching wildcard *.crt, *.key, *.p12. USE WITH CAUTION.
  --windowsInstallation
                        Displays the installation instructions for Windows
```

# IMPORTANT
Everytime you run the `--generateRootCA` or `--generateClientCertificate` argument, it will `_overwrite_` existing files. 
This can lead to a new Root CA being generated that doesn't match the Client Certificate (if that happened to be run beforehand)

## Generate Root CA
```bash
$ python3 generate-certificate.py --companyName "Test123,. Inc" --generateRootCA 
----------------------------------------------------------------------------
DISCLAIMER:
These files are not meant for production environments. Use at your own risk.
----------------------------------------------------------------------------
Root CA certificate filename - root-ca-test-inc.crt
Root CA private key filename - root-ca-test-inc.key
```

## Generate Root CA with PKCS12 file
This will create a p12 file with a randomly generated passphrase (outputted to stdout).
```bash
$ python3 generate-certificate.py --companyName "Test123, Inc" --generateRootCA --generatePKCS12
----------------------------------------------------------------------------
DISCLAIMER:
These files are not meant for production environments. Use at your own risk.
----------------------------------------------------------------------------
Root CA certificate filename - root-ca-test-inc.crt
Root CA private key filename - root-ca-test-inc.key
Password for root-ca-test-inc.p12 is thisisnotreallyapassword
```

In order to run the below commands, you need to run the `--generateRootCA` argument first. If the Root CA files haven't been generated, an error like this will appear:
```bash
$ python3 generate-certificate.py --companyName "Test123, Inc" --generateClientCertificate
Root CA public key and private key do not exist.
Exiting.
```

## Generate Client Certificate
```bash
$ python3 generate-certificate.py --companyName "Test123, Inc" --generateClientCertificate
----------------------------------------------------------------------------
DISCLAIMER:
These files are not meant for production environments. Use at your own risk.
----------------------------------------------------------------------------
Client certificate private key filename - client-cert-test-inc.key
Client certificate public key filename - client-cert-test-inc.crt
```

## Generate Client Certificate with PKCS12 file
```bash
$ python3 generate-certificate.py --companyName "Test123, Inc" --generateClientCertificate --generatePKCS12
----------------------------------------------------------------------------
DISCLAIMER:
These files are not meant for production environments. Use at your own risk.
----------------------------------------------------------------------------
Client certificate private key filename - client-cert-test-inc.key
Client certificate public key filename - client-cert-test-inc.crt
Password for client-cert-test-inc.p12 is thisisnotreallyapassword
```

## Generate Client Certificate with PKCS12 file and add Windows Installation Instructions
```bash
$ python3 generate-certificate.py --companyName "Test123, Inc" --generateClientCertificate --generatePKCS12 --windowsInstallation
----------------------------------------------------------------------------
DISCLAIMER:
These files are not meant for production environments. Use at your own risk.
----------------------------------------------------------------------------
Client certificate private key filename - client-cert-test-inc.key
Client certificate public key filename - client-cert-test-inc.crt
Password for client-cert-test-inc.p12 is thisisnotreallyapassword
----------------------------------------------------------------------------
Windows Installation (from the directory where files are stored):
To install Client Authentication certificate into User certificate store (in both cases, click yes to install Root CA as well):
C:\>certutil -importpfx -f -user -p thisisnotreallyapassword client-cert-test-inc.p12 NoExport

To install certificate into Local Machine certificate store:
C:\>certutil -importpfx -f -Enterprise -p thisisnotreallyapassword client-cert-test-inc.p12 NoExport
```

## Generate Client Certificate with DNSName or userPrincipalName in Subject Alternative Name (SAN)
Make sure to edit the field first (under `def certificateMetaData`):
```python
certificateInfo['ClientAuthentication']['oid']['subjectAlternativeName']['DNSName']
```
```bash
$ python3 generate-certificate.py --companyName "Test123 Inc" --generateClientCertificate --generatePKCS12 --dnsName
```
OR

Make sure to edit the field first (under `def certificateMetaData`):
```python
certificateInfo['ClientAuthentication']['oid']['subjectAlternativeName']['userPrincipalName']
```
```bash
$ python3 generate-certificate.py --companyName "Test123 Inc" --generateClientCertificate --generatePKCS12 --userPrincipalName
```

## Remove files generated by script
To remove all files generated by the script
```bash
$ python generate-certificate.py --removeAllCertsAndKeys
```


# :closed_lock_with_key: :closed_lock_with_key: :closed_lock_with_key: Advanced :closed_lock_with_key: :closed_lock_with_key: :closed_lock_with_key:
WARNING - editing this below is at your own risk. There is no error checking by changing these values and the script will throw back an error if they're not properly defined.

My recommendation is to leave the following fields:
## Under `RootCertificateAuthority.json`
* `CN`
* `companyName`
* `extensions`

## Under `ClientCertificate.json`
* `CN`
* `extensions`

If you'd like to edit how the certificates are generated, there are 2 files that can be edited.

## Sample `RootCertificateAuthority.json`
```json
{
    "oid": {
        "CN": null,
        "companyName": null,
        "organizationalUnit": "Client Authentication CA",
        "locality": null,
        "stateOrProvince": null,
        "organizationName": null,
        "countryName": null,
        "domainComponent": [null]
    },
    "rsa": {
        "rsa_bits": 2048,
        "digest": "sha512"
    },
    "ecc": {
        "curve": "secp256r1",
        "digest": "sha512"
    },
    "extensions": {
        "keyUsage": ["digitalSignature", "nonRepudiation", "keyCertSign"],
        "extendedKeyUsage": ["clientAuth"]
    }
}
```

## Sample `ClientAuthentication.json`
```json
{
    "oid": {
        "CN": "Endpoint Client Authentication",
        "organizationalUnit": "Client Authentication",
        "locality": null,
        "stateOrProvince": null,
        "organizationName": null,
        "countryName": null,
        "domainComponent": [null],
        "subjectAlternativeName": {
            "DNSName": null,
            "userPrincipalName": null
        }
    },
    "rsa": {
        "rsa_bits": 2048,
        "digest": "sha256"
    },
    "ecc": {
        "curve": "secp256r1",
        "digest": "sha256"
    },
    "extensions": {
        "keyUsage": ["digitalSignature", "nonRepudiation"],
        "extendedKeyUsage": ["clientAuth"]
    }
}
```
