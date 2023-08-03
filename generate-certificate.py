# Description:     Create a Root CA with a client Authentication certificate that's signed by the Root CA.
# Author:          TheScriptGuy
# Last modified:   2023-08-02
# Version:         1.08

from cryptography import x509

from pyasn1.type import char
from pyasn1.codec.der import encoder as der_encoder

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from CryptographySupport import CryptographySupport, CryptographyFileOperations

import datetime

import sys
import os
import argparse
import random
import idna

scriptVersion = "1.08"


def certificateMetaData():
    """Generate certificate structure based on supplied information."""
    # Let's normalize the companyName - only leave numbers and letters
    normalizedName = ''.join(filter(lambda x: x.isalpha() or x.isspace() or x.isdigit(), args.companyName))

    # Replace spaces with hyphens for Root Certificate Authority.
    rootCAFileName = "root-ca-" + normalizedName.replace(' ', '-').lower()

    # Replace spaces with hyphens for Client Certificate information.
    clientCertificateFileName = "client-cert-" + normalizedName.replace(' ', '-').lower()

    certificateInfo = {
        "RootCA": {
            "oid": {
                "CN": f"{args.companyName} Root CA",
                "companyName": args.companyName,
                "organizationalUnit": "Client Authentication CA",
                "locality": None,
                "stateOrProvince": None,
                "organizationName": None,
                "countryName": None,
                "domainComponent": [None],
            },
            "rootCAFileName": rootCAFileName,
            "rootCAPublicKey": f"{rootCAFileName}.crt",
            "rootCAPrivateKey": f"{rootCAFileName}.key",
            "rootCAPKCS12": f"{rootCAFileName}.p12",
            "notBefore": datetime.datetime.now(),
            "notAfter": datetime.datetime.now()
            + datetime.timedelta(seconds=31536000),
            "rsa": {
                "rsa_bits": 2048,
                "digest": "sha512",
            },
            "ecc": {
                "curve": "secp256r1",
                "digest": "sha512",
            },
            "extensions": {
                "keyUsage": [
                    "digitalSignature",
                    "nonRepudiation",
                    "keyCertSign",
                ],
                "extendedKeyUsage": ["clientAuth"],
            },
        }
    }
    # Client Authentication certificate information. Edit at your own risk.
    certificateInfo["ClientAuthentication"] = {
        "oid": {
            "CN": "Endpoint Client Authentication",
            "organizationalUnit": "Client Authentication",
            "locality": None,
            "stateOrProvince": None,
            "organizationName": None,
            "countryName": None,
            "domainComponent": [None],
            "subjectAlternativeName": {
                "DNSName": None,
                "userPrincipalName": None,
            },
        },
        "clientCertificatePublicKey": f"{clientCertificateFileName}.crt",
        "clientCertificatePrivateKey": f"{clientCertificateFileName}.key",
        "clientCertificatePKCS12": f"{clientCertificateFileName}.p12",
        "notBefore": datetime.datetime.now(),
        "notAfter": datetime.datetime.now()
        + datetime.timedelta(seconds=31536000),
        "rsa": {
            "rsa_bits": 2048,
            "digest": "sha256",
        },
        "ecc": {
            "curve": "secp256r1",
            "digest": "sha256",
        },
        "extensions": {
            "keyUsage": ["digitalSignature", "nonRepudiation"],
            "extendedKeyUsage": ["clientAuth"],
        },
    }

    return certificateInfo


def parseArguments():
    """Create argument options and parse through them to determine what to do with script."""
    # Instantiate the parser
    parser = argparse.ArgumentParser(
        description=f'Certificate Generation v{scriptVersion}'
    )

    # Optional arguments
    parser.add_argument('--companyName', default='ACME Corp',
                        help='Entity/Company name for the certificates.')

    parser.add_argument('--generateRootCA', action='store_true',
                        help='Generate the Root CA certificate and key. Uses --companyName in certificate creation.')

    parser.add_argument('--generateClientCertificate', action='store_true',
                        help='Generate the client certificate to use for client authentication.')

    parser.add_argument('--generatePKCS12', action='store_true',
                        help='generate a PKCS12 type file.')

    parser.add_argument('--nonRestrictiveRootCA', action='store_true',
                        help='Remove Root CA extensions. USE WITH CAUTION.')

    parser.add_argument('--ecc', action='store_true',
                        help='Use Elliptic Curves in preference to RSA.')

    parser.add_argument('--dnsName', action='store_true',
                        help='Add a Subject Alternative Name (SAN) for the DNS hostname.')

    parser.add_argument('--userPrincipalName', action='store_true',
                        help='Add a Subject Alternative Name (SAN) for the Windows User Principal Name (UPN).')

    parser.add_argument('--removeAllCertsAndKeys', action='store_true',
                        help='Removes all files matching wildcard *.crt, *.key, *.p12. USE WITH CAUTION.')

    parser.add_argument('--windowsInstallation', action='store_true',
                        help='Displays the installation instructions for Windows')

    global args
    args = parser.parse_args()


def printDisclaimer():
    """Disclaimer for using the certificates."""
    print("-" * 76)
    print("DISCLAIMER:")
    print("These files are not meant for production environments. Use at your own risk.")
    print("-" * 76)


def printWindowsInstallationInstructions(
        __certificateInfo: dict,
        __p12Password: str
        ) -> None:
    """Display the installation instructions for Windows."""
    print("-" * 76)
    print("Windows Installation (from the directory where files are stored):")
    print("To install Client Authentication certificate into User certificate store (in both cases, click yes to install Root CA as well):")
    print(f"C:\\>certutil -importpfx -f -user -p {__p12Password} {__certificateInfo['ClientAuthentication']['clientCertificatePKCS12']} NoExport")
    print()
    print("To install certificate into Local Machine certificate store:")
    print(f"C:\\>certutil -importpfx -f -Enterprise -p {__p12Password} {__certificateInfo['ClientAuthentication']['clientCertificatePKCS12']} NoExport")


def create_root_private_keys(__certificateMetaData: dict) -> CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES:
    """Create a private key."""
    return (
        ec.generate_private_key(
            curve=CryptographySupport.CryptographySupport.generate_curve(
                __certificateMetaData["RootCA"]["ecc"]["curve"]
            ),
            backend=default_backend(),
        )
        if args.ecc
        else rsa.generate_private_key(
            public_exponent=65537,
            key_size=__certificateMetaData["RootCA"]["rsa"]["rsa_bits"],
            backend=default_backend(),
        )
    )


def create_client_private_keys(__certificateMetaData: dict) -> CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES:
    """Create a private key."""
    return (
        ec.generate_private_key(
            curve=CryptographySupport.CryptographySupport.generate_curve(
                __certificateMetaData["ClientAuthentication"]["ecc"]["curve"]
            ),
            backend=default_backend(),
        )
        if args.ecc
        else rsa.generate_private_key(
            public_exponent=65537,
            key_size=__certificateMetaData["ClientAuthentication"]["rsa"][
                "rsa_bits"
            ],
            backend=default_backend(),
        )
    )


def createRootCA(__certificateMetaData: dict) -> None:
    """Create a Root CA with the information from the --companyName argument."""
    rootCAPrivateKey = create_root_private_keys(__certificateMetaData)

    rootCAPublicKey = rootCAPrivateKey.public_key()
    rootCACertificateBuilder = x509.CertificateBuilder()

    # Start building the attributes for the Root CA certificate
    rootCANameAttributes = CryptographySupport.CryptographySupport.build_name_attribute(__certificateMetaData["RootCA"])
    rootCACertificateBuilder = rootCACertificateBuilder.subject_name(x509.Name(rootCANameAttributes))
    rootCACertificateBuilder = rootCACertificateBuilder.issuer_name(x509.Name(rootCANameAttributes))

    # Generate a random serial number
    rootSerialNumber = random.getrandbits(64)

    rootCACertificateBuilder = rootCACertificateBuilder.not_valid_before(__certificateMetaData["RootCA"]["notBefore"])
    rootCACertificateBuilder = rootCACertificateBuilder.not_valid_after(__certificateMetaData["RootCA"]["notAfter"])
    rootCACertificateBuilder = rootCACertificateBuilder.serial_number(rootSerialNumber)
    rootCACertificateBuilder = rootCACertificateBuilder.public_key(rootCAPublicKey)

    """
    By default, restrictive extensions are always applied.
    Do not use this option unless absolutely necessary.
    The idea being that you don't want a Root CA that can sign any type of certificate and
    create a security problem.
    """
    if not args.nonRestrictiveRootCA:
        rootCAKeyUsage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_cert_sign=True,
            key_agreement=False,
            content_commitment=True,
            data_encipherment=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

        # Add the extensions to the rootCACertificateBuilder object.
        rootCACertificateBuilder = rootCACertificateBuilder.add_extension(
            rootCAKeyUsage, True
        )

        # Create the ExtendedKeyUsage list
        rootCAExtendedKeyUsage = CryptographySupport.CryptographySupport.build_extended_key_usage(__certificateMetaData['RootCA'])

        # Add extension for only allowing CA to do Client Authentication
        rootCACertificateBuilder = rootCACertificateBuilder.add_extension(
            x509.ExtendedKeyUsage(rootCAExtendedKeyUsage), critical=True
        )

    # Apply basic constraints to certificate.
    rootCACertificateBuilder = rootCACertificateBuilder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        )

    # Sign the certificate.
    rootCACertificate = rootCACertificateBuilder.sign(
        private_key=rootCAPrivateKey,
        algorithm=CryptographySupport.CryptographySupport.generate_hash(__certificateMetaData["RootCA"]["rsa"]["digest"]),
        backend=default_backend()
    )

    # Print the disclaimer.
    printDisclaimer()

    # Write private key to file
    if CryptographyFileOperations.CryptographyFileOperations.write_private_key_to_file(rootCAPrivateKey, __certificateMetaData['RootCA']['rootCAPrivateKey']):
        print(f"Root CA private key filename - {__certificateMetaData['RootCA']['rootCAPrivateKey']}")
    else:
        print(f"Error writing to file {__certificateMetaData['RootCA']['rootCAPrivateKey']}")
        sys.exit(1)

    # Write the public key to file.
    if CryptographyFileOperations.CryptographyFileOperations.write_public_key_to_file(rootCACertificate, __certificateMetaData["RootCA"]["rootCAPublicKey"]):
        print(f"Root CA certificate filename - {__certificateMetaData['RootCA']['rootCAPublicKey']}")
    else:
        print(f"Error writing to file {__certificateMetaData['RootCA']['rootCAPublicKey']}")
        sys.exit(1)

    if root_ca_passphrase := CryptographyFileOperations.CryptographyFileOperations.write_rootca_pkcs12(
        __certificateMetaData, rootCAPrivateKey, rootCACertificate
    ):
        if args.generatePKCS12:
            print(f"Password for {__certificateMetaData['RootCA']['rootCAPKCS12']} is {root_ca_passphrase}")

            if args.windowsInstallation:
                printWindowsInstallationInstructions(__certificateMetaData, root_ca_passphrase)


def check_root_ca_files_exist(__certificateMetaData: dict) -> None:
    """
    This will check to see if the root CA public and private key exist.
    If not, exit with system code 1.
    """
    if not (os.path.isfile(__certificateMetaData["RootCA"]["rootCAPublicKey"]) and os.path.isfile(__certificateMetaData["RootCA"]["rootCAPrivateKey"])):
        print("Root CA public key and private key do not exist.")
        print("Exiting.")
        sys.exit(1)


def create_client_certificate(__certificateMetaData: dict) -> None:
    """Create the client certificate and sign it from the root CA created from createRootCA()"""
    check_root_ca_files_exist(__certificateMetaData)

    clientPrivateKey = create_client_private_keys(__certificateMetaData)

    clientPublicKey = clientPrivateKey.public_key()

    clientNameAttributes = CryptographySupport.CryptographySupport.build_name_attribute(__certificateMetaData['ClientAuthentication'])

    clientCertificateBuilder = x509.CertificateBuilder()
    clientCertificateBuilder = clientCertificateBuilder.subject_name(x509.Name(clientNameAttributes))

    rootCANameAttributes = CryptographySupport.CryptographySupport.build_name_attribute(__certificateMetaData['RootCA'])
    clientCertificateBuilder = clientCertificateBuilder.issuer_name(x509.Name(rootCANameAttributes))

    # Generate a random serial number
    clientSerialNumber = random.getrandbits(64)

    clientCertificateBuilder = clientCertificateBuilder.not_valid_before(__certificateMetaData["ClientAuthentication"]["notBefore"])
    clientCertificateBuilder = clientCertificateBuilder.not_valid_after(__certificateMetaData["ClientAuthentication"]["notAfter"])
    clientCertificateBuilder = clientCertificateBuilder.serial_number(clientSerialNumber)
    clientCertificateBuilder = clientCertificateBuilder.public_key(clientPublicKey)

    # Create a list of extensions to be added to certificate.
    clientCertificateBuilder = clientCertificateBuilder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    # Add extended key usage extensions to the certificate
    clientCertificateExtendedKeyUsage = CryptographySupport.CryptographySupport.build_extended_key_usage(__certificateMetaData['ClientAuthentication'])
    clientCertificateBuilder = clientCertificateBuilder.add_extension(
        x509.ExtendedKeyUsage(clientCertificateExtendedKeyUsage), critical=True
    )

    # Add Subject Alternative Name extensions
    if args.dnsName:
        # The DNSName needs to be attached to the Subject Alternative Name.

        # First check to see if the dnsName has been defined in the dict.
        if __certificateMetaData['ClientAuthentication']['oid']['subjectAlternativeName']['DNSName'] is not None:
            __dnsName = __certificateMetaData['ClientAuthentication']['oid']['subjectAlternativeName']['DNSName']
            __a_dnsName = idna.encode(__dnsName).decode('ascii')
            clientCertificateBuilder = clientCertificateBuilder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(__a_dnsName)]
                    ), critical=False
            )
        else:
            # The required key: value pair was not set. Print error message and exit.
            print("The required key: value pair was not set for DNSName.")
            sys.exit(1)

    if args.userPrincipalName:
        # The User Principal Name needs to be attached to the Subject Alternative Name.
        if __certificateMetaData['ClientAuthentication']['oid']['subjectAlternativeName']['userPrincipalName'] is not None:
            # UPN field
            upn_value = __certificateMetaData['ClientAuthentication']['oid']['subjectAlternativeName']['userPrincipalName']
            upn_value = der_encoder.encode(char.UTF8String(upn_value))  # ASN.1 DER encoding
            upn_field = x509.OtherName(x509.oid.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3'), upn_value)

            clientCertificateBuilder = clientCertificateBuilder.add_extension(
                x509.SubjectAlternativeName(
                    [upn_field]
                    ), critical=False
            )
        else:
            # The required key: value pair was not set. Print error message and exit.
            print("The required key: value pair was not set for userPrincipalName.")
            sys.exit(1)

    # Load Root CA Key
    with open(__certificateMetaData["RootCA"]["rootCAPrivateKey"], "rb") as f_rootCAKeyFile:
        rootCAkeyPEM = serialization.load_pem_private_key(f_rootCAKeyFile.read(), password=None)

    # Sign the certificate based off the Root CA key.
    clientAuthenticationCertificate = clientCertificateBuilder.sign(
        private_key=rootCAkeyPEM,
        algorithm=CryptographySupport.CryptographySupport.generate_hash(__certificateMetaData["ClientAuthentication"]["rsa"]["digest"]),
        backend=default_backend()
    )

    clientPublicKey = clientPrivateKey.public_key()

    # Print the disclaimer.
    printDisclaimer()

    # Client the client private key to file.
    if CryptographyFileOperations.CryptographyFileOperations.write_client_private_key(clientPrivateKey, __certificateMetaData["ClientAuthentication"]["clientCertificatePrivateKey"]):
        print(f"Client certificate private key filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePrivateKey']}")
    else:
        print(f"Error when writing client private key to {__certificateMetaData['ClientAuthentication']['clientCertificatePrivateKey']}")
        sys.exit(1)

    # Write the client certificate to file.
    if CryptographyFileOperations.CryptographyFileOperations.write_client_public_key(clientPublicKey, __certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']):
        print(f"Client certificate filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']}")
    else:
        print(f"Error when writing client public key to {__certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']}")
        sys.exit(1)

    if args.generatePKCS12:
        # Generate a PKCS12 File for the Client Certificate Authenticate.
        client_certificate_passphrase = CryptographyFileOperations.CryptographyFileOperations.write_client_certificate_pkcs12(
            __certificateMetaData,
            clientPrivateKey,
            clientAuthenticationCertificate
        )
        if client_certificate_passphrase:
            print(f"Password for {__certificateMetaData['ClientAuthentication']['clientCertificatePKCS12']} is {client_certificate_passphrase}")

        if args.windowsInstallation:
            printWindowsInstallationInstructions(__certificateMetaData, client_certificate_passphrase)


def main():
    """The main definition."""
    # Parse arguments for the script.
    parseArguments()

    # Check to see if we need to remove all certificates, private keys, and PKCS12 formatted files.
    if args.removeAllCertsAndKeys:
        CryptographyFileOperations.CryptographyFileOperations.remove_all_certs_and_keys()
        sys.exit(0)

    # Setup the template for the certificate structure for both Root CA and Client Certificate.
    myCertMetaData = certificateMetaData()

    # Adding logic handling for when only --companyName is passed.
    if (
        args.companyName
        and not args.generateRootCA
        and not args.generateClientCertificate
    ):
        print("Missing --generateRootCA or --generateClientCertificate Argument.")
        sys.exit(1)

    # First check to see if only one argument was passed
    # Can only be --dnsName or --userPrincipalName, but not both. Exit if true.
    if args.dnsName and args.userPrincipalName:
        # Print an error message and exit.
        print("Please use either --dnsName or --userPrincipalName, but not both.")
        sys.exit(1)

    # Check to see if Root CA needs to be generated.
    if args.generateRootCA and args.companyName:
        createRootCA(myCertMetaData)

    # Check to see if Client Certificate needs to be generated.
    if args.generateClientCertificate and args.companyName:
        create_client_certificate(myCertMetaData)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        print()
        try:
            sys.exit(0)
        except SystemExit:
            os.exit(0)
