# Description:     Create a Root CA with a client Authentication certificate that's signed by the Root CA.
# Author:          TheScriptGuy
# Last modified:   2023-05-19
# Version:         1.04
from os.path import join

from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography_support import cryptography_support

from cryptography.x509.oid import NameOID
from typing import Union

import datetime

import random
import sys
import os
import argparse
import glob

scriptVersion = "1.04"


def certificateMetaData():
    """Generate certificate structure based on supplied information."""
    certificateInfo = {}

    # Let's normalize the companyName - only leave numbers and letters
    normalizedName = ''.join(filter(lambda x: x.isalpha() or x.isspace() or x.isdigit(), args.companyName))

    # Replace spaces with hyphens for Root Certificate Authority.
    rootCAFileName = "root-ca-" + normalizedName.replace(' ', '-').lower()

    # Replace spaces with hyphens for Client Certificate information.
    clientCertificateFileName = "client-cert-" + normalizedName.replace(' ', '-').lower()

    # Root Certificate Authority information. Edit at your own risk.
    certificateInfo["RootCA"] = {
        "oid": {
            "CN": args.companyName + " Root CA",
            "companyName": args.companyName,
            "organizationalUnit": "Client Authentication CA",
            "locality": None,
            "stateOrProvince": None,
            "organizationName": None,
            "countryName": None,
            "domainComponent": [None]
        },
        "rootCAFileName": rootCAFileName,
        "rootCAPublicKey": f"{rootCAFileName}.crt",
        "rootCAPrivateKey": f"{rootCAFileName}.key",
        "rootCAPKCS12": f"{rootCAFileName}.p12",
        "notBefore": datetime.datetime.today(),
        "notAfter": datetime.datetime.today() + datetime.timedelta(seconds=31536000),
        "rsa": {
            "rsa_bits": 2048,
            "digest": "sha512",
        },
        "ecc": {
            "curve": "secp256r1",
            "digest": "sha512"
        },
        "extensions": {
            "keyUsage": "digitalSignature, nonRepudiation, keyCertSign",
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
            "countryName": "US",
            "domainComponent": [None]
        },
        "clientCertificatePublicKey": f"{clientCertificateFileName}.crt",
        "clientCertificatePrivateKey": f"{clientCertificateFileName}.key",
        "clientCertificatePKCS12": f"{clientCertificateFileName}.p12",
        "notBefore": datetime.datetime.today(),
        "notAfter": datetime.datetime.today() + datetime.timedelta(seconds=31536000),
        "rsa": {
            "rsa_bits": 2048,
            "digest": "sha256",
        },
        "ecc": {
            "curve": "secp256r1",
            "digest": "sha256"
        },
        "extensions": {
            "keyUsage": "digitalSignature, nonRepudiation",
            "extendedKeyUsage": "clientAuth"
        }
    }

    return certificateInfo


def parseArguments():
    """Create argument options and parse through them to determine what to do with script."""
    # Instantiate the parser
    parser = argparse.ArgumentParser(description='Certificate Generation v' + scriptVersion)

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

    parser.add_argument('--removeAllCertsAndKeys', action='store_true',
                        help='Removes all files matching wildcard *.crt, *.key, *.p12. USE WITH CAUTION.')

    parser.add_argument('--windowsInstallation', action='store_true',
                        help='Displays the installation instructions for Windows')

    global args
    args = parser.parse_args()


def generatePassphrase(__passwordLength: int):
    """Generate a random password based on the length supplied."""

    # Define the valid letters for the password.
    validLetters = "abcdefghijklmnopqrstuvwxyz"

    # Define the valid numbers for the password.
    validNumbers = "0123456789"

    # Combine the list of valid letters and numbers
    validCharacters = validLetters + validNumbers

    # Create a new password based off validCharacters and the length defined by __passwordLength
    newPassphrase = "".join(random.choice(validCharacters) for i in range(__passwordLength))

    return newPassphrase


def removeAllCertsAndKeys():
    """Removes all files that were generated by this script."""
    # Remove .p12 files
    for iFile in glob.glob("*.p12"):
        print(f"Removing file {iFile}")
        os.remove(iFile)

    # Remove .crt files
    for iFile in glob.glob("*.crt"):
        print(f"Removing file {iFile}")
        os.remove(iFile)

    # Remove .key files
    for iFile in glob.glob("*.key"):
        print(f"Removing file {iFile}")
        os.remove(iFile)


def printDisclaimer():
    """Disclaimer for using the certificates."""
    print("----------------------------------------------------------------------------")
    print("DISCLAIMER:")
    print("These files are not meant for production environments. Use at your own risk.")
    print("----------------------------------------------------------------------------")


def printWindowsInstallationInstructions(
        __certificateInfo: dict,
        __p12Password: str
        ) -> None:
    """Display the installation instructions for Windows."""
    print("----------------------------------------------------------------------------")
    print("Windows Installation (from the directory where files are stored):")
    print("To install Client Authentication certificate into User certificate store (in both cases, click yes to install Root CA as well):")
    print(f"C:\\>certutil -importpfx -f -user -p {__p12Password} {__certificateInfo['ClientAuthentication']['clientCertificatePKCS12']} NoExport")
    print()
    print("To install certificate into Local Machine certificate store:")
    print(f"C:\\>certutil -importpfx -f -Enterprise -p {__p12Password} {__certificateInfo['ClientAuthentication']['clientCertificatePKCS12']} NoExport")


def write_private_key_to_file(
        __private_key: cryptography_support.cryptography_support.private_key_types,
        __filename: str
        ) -> bool:
    """Write the __private_key of a certificate to __filename."""
    # Assume that we'll be successful when writing to the file.
    successful_write = True

    try:
        with open(__filename, "wb") as f_PrivateKey:
            f_PrivateKey.write(
                __private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    except:
        # Could not write to file.
        successful_write = False

    return successful_write


def write_public_key_to_file(
        __public_key: cryptography_support.cryptography_support.public_key_types,
        __filename: str
        ) -> bool:
    """Write __public_key of a certificate to __filename."""
    # Assume that we'll be successful when writing to the file.
    successful_write = True

    try:
        with open(__filename, "wb") as f_PublicKey:
            f_PublicKey.write(
                __public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                )
            )
    except:
        # Could not write to file.
        successful_write = False

    return successful_write


def write_rootca_pkcs12(
        __certificateMetaData: dict,
        __rootCAPrivateKey: cryptography_support.cryptography_support.private_key_types,
        __rootCACertificate: x509.Certificate
        ) -> None:
    """Combine both the __rootCAPrivateKey and __rootCACertificate into pkcs12 file format."""
    # Create new 30 character passphrase for the Root CA.
    newPassphrase = generatePassphrase(30)

    rootCAPKCS12 = serialization.pkcs12.serialize_key_and_certificates(
        name=__certificateMetaData['RootCA']['oid']['companyName'].encode('ascii'),
        key=__rootCAPrivateKey,
        cert=__rootCACertificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(newPassphrase.encode('ascii'))
    )

    # Write the PKCS12 file to disk.
    with open(__certificateMetaData['RootCA']['rootCAPKCS12'], 'wb') as rootCAPKCS12file:
        rootCAPKCS12file.write(rootCAPKCS12)

    print(f"Password for {__certificateMetaData['RootCA']['rootCAPKCS12']} is {newPassphrase}")


def build_name_attribute(
        certificateAttributes: dict
    ) -> list:
    """Build a list of all the x509 named attributes in the supplied dict."""
    # Create an empty list name_attribute_list
    name_attribute_list = []

    for item in certificateAttributes['oid']:
        if certificateAttributes['oid'][item] is not None:
            match item:
                case "CN":
                    name_attribute_list.append(x509.NameAttribute(NameOID.COMMON_NAME, certificateAttributes['oid'][item]))
                case "companyName":
                    name_attribute_list.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, certificateAttributes['oid'][item]))
                case "organizationalUnit":
                    name_attribute_list.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, certificateAttributes['oid'][item]))
                case "locality":
                    name_attribute_list.append(x509.NameAttribute(NameOID.LOCALITY_NAME, certificateAttributes['oid'][item]))
                case "stateOrProvince":
                    name_attribute_list.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, certificateAttributes['oid'][item]))
                case "countryName":
                    name_attribute_list.append(x509.NameAttribute(NameOID.COUNTRY_NAME, certificateAttributes['oid'][item]))
                case "domainComponent":
                    if certificateAttributes['oid'][item] != [None]:
                        for dc in certificateAttributes['oid'][item]:
                            name_attribute_list.append(x509.NameAttribute(NameOID.DOMAIN_COMPONENT, dc))

    return name_attribute_list


def createRootCA(__certificateMetaData: dict) -> None:
    """Create a Root CA with the information from the --companyName argument."""
    # First check to see if the --ecc argument was passed. If passed, generate ECC key.
    if args.ecc:
        rootCAPrivateKey = ec.generate_private_key(
            curve=cryptography_support.cryptography_support.generateCurve(__certificateMetaData["RootCA"]["ecc"]["curve"]),
            backend=default_backend()
        )
    else:
        rootCAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=__certificateMetaData["RootCA"]["rsa"]["rsa_bits"],
            backend=default_backend()
        )

    rootCAPublicKey = rootCAPrivateKey.public_key()
    rootCACertificateBuilder = x509.CertificateBuilder()

    # Start building the attributes for the Root CA certificate
    rootCANameAttributes = build_name_attribute(__certificateMetaData["RootCA"])
    rootCACertificateBuilder = rootCACertificateBuilder.subject_name(x509.Name(rootCANameAttributes))
    rootCACertificateBuilder = rootCACertificateBuilder.issuer_name(x509.Name(rootCANameAttributes)
    )

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
        rootCACertificateBuilder = rootCACertificateBuilder.add_extension(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]), critical=True
        )

    # Apply basic constraints to certificate.
    rootCACertificateBuilder = rootCACertificateBuilder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        )

    # Sign the certificate.
    rootCACertificate = rootCACertificateBuilder.sign(
        private_key=rootCAPrivateKey, algorithm=cryptography_support.cryptography_support.generateHash(__certificateMetaData["RootCA"]["rsa"]["digest"]),
        backend=default_backend()
    )

    # Print the disclaimer.
    printDisclaimer()

    # Write private key to file
    if write_private_key_to_file(rootCAPrivateKey, __certificateMetaData['RootCA']['rootCAPrivateKey']):
        print(f"Root CA private key filename - {__certificateMetaData['RootCA']['rootCAPrivateKey']}")
    else:
        print(f"Error writing to file {__certificateMetaData['RootCA']['rootCAPrivateKey']}")
        sys.exit(1)

    # Write the public key to file.
    if write_public_key_to_file(rootCACertificate, __certificateMetaData["RootCA"]["rootCAPublicKey"]):
        print(f"Root CA certificate filename - {__certificateMetaData['RootCA']['rootCAPublicKey']}")
    else:
        print(f"Error writing to file {__certificateMetaData['RootCA']['rootCAPublicKey']}")
        sys.exit(1)

    if args.generatePKCS12:
        # Generate a PKCS12 file for the Root CA.
        write_rootca_pkcs12(__certificateMetaData, rootCAPrivateKey, rootCACertificate)


def checkRootCAFilesExist(__certificateMetaData: dict) -> None:
    """
    This will check to see if the root CA public and private key exist.
    If not, exit with system code 1.
    """
    if not (os.path.isfile(__certificateMetaData["RootCA"]["rootCAPublicKey"]) and os.path.isfile(__certificateMetaData["RootCA"]["rootCAPrivateKey"])):
        print("Root CA public key and private key do not exist.")
        print("Exiting.")
        sys.exit(1)


def write_client_certificate_pkcs12(
        __certificateMetaData: dict,
        __clientPrivateKey: cryptography_support.cryptography_support.private_key_types,
        __clientAuthenticationCertificate: x509.Certificate
        ) -> None:
    """Write the client certificate and Root CA into the PKCS12 file."""
    # Get the Root CA certificate file
    with open(__certificateMetaData["RootCA"]["rootCAPublicKey"], "rb") as f_rootCAKeyFile:
        rootCAPublicKeyPEM = x509.load_pem_x509_certificate(f_rootCAKeyFile.read())

    # Create new 30 character passphrase for the Root CA.
    newPassphrase = generatePassphrase(10)

    # Create the PKCS12 object.
    clientAuthenticationPKCS12 = serialization.pkcs12.serialize_key_and_certificates(
        name=__certificateMetaData['RootCA']['oid']['companyName'].encode('ascii'),
        key=__clientPrivateKey,
        cert=__clientAuthenticationCertificate,
        cas=[rootCAPublicKeyPEM],
        encryption_algorithm=serialization.BestAvailableEncryption(newPassphrase.encode('ascii'))
    )

    # Write the PKCS12 file to disk.
    with open(__certificateMetaData['ClientAuthentication']['clientCertificatePKCS12'], 'wb') as f_clientAuthenticationPKCS12file:
        f_clientAuthenticationPKCS12file.write(clientAuthenticationPKCS12)

    print(f"Password for {__certificateMetaData['ClientAuthentication']['clientCertificatePKCS12']} is {newPassphrase}")


def write_client_private_key(
        __private_key: cryptography_support.cryptography_support.private_key_types,
        __filename: str
        ) -> bool:
    """Writes the client private key to __filename."""
    successful_write = True

    try:
        with open(__filename, "wb") as f_clientPrivateKey:
            f_clientPrivateKey.write(
                __private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    except:
        successful_write = False

    return successful_write

def write_client_public_key(
        __public_key: cryptography_support.cryptography_support.public_key_types,
        __filename: str
        ) -> bool:
    """Write the client public key to __filename."""
    successful_write = True

    try:
        with open(__filename, "wb") as f_clientPublicKey:
            f_clientPublicKey.write(
                __public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    except:
        successful_write = False

    return successful_write

def createClientCertificate(__certificateMetaData: dict) -> None:
    """Create the client certificate and sign it from the root CA created from createRootCA()"""
    checkRootCAFilesExist(__certificateMetaData)

    # First check to see if the --ecc argument was passed. If passed, generate ECC key.
    if args.ecc:
        clientPrivateKey = ec.generate_private_key(
            curve=cryptography_support.cryptography_support.generateCurve(__certificateMetaData["ClientAuthentication"]["ecc"]["curve"]),
            backend=default_backend()
        )
    else:
        clientPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=__certificateMetaData["ClientAuthentication"]["rsa"]["rsa_bits"],
            backend=default_backend()
        )

    clientPublicKey = clientPrivateKey.public_key()

    clientNameAttributes = build_name_attribute(__certificateMetaData['ClientAuthentication'])
    clientCertificateBuilder = x509.CertificateBuilder()
    clientCertificateBuilder = clientCertificateBuilder.subject_name(x509.Name(clientNameAttributes))

    rootCANameAttributes = build_name_attribute(__certificateMetaData['RootCA'])
    clientCertificateBuilder = clientCertificateBuilder.issuer_name(x509.Name(rootCANameAttributes))

    # Generate a random serial number
    clientSerialNumber = random.getrandbits(64)

    clientCertificateBuilder = clientCertificateBuilder.not_valid_before(__certificateMetaData["ClientAuthentication"]["notBefore"])
    clientCertificateBuilder = clientCertificateBuilder.not_valid_after(__certificateMetaData["ClientAuthentication"]["notAfter"])
    clientCertificateBuilder = clientCertificateBuilder.serial_number(clientSerialNumber)
    clientCertificateBuilder = clientCertificateBuilder.public_key(clientPublicKey)

    # Create a list of extensions to be added to certificate.
    clientCertificateBuilder = clientCertificateBuilder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    )
    clientCertificateBuilder = clientCertificateBuilder.add_extension(
        x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]), critical=True
    )

    # Load Root CA Key
    with open(__certificateMetaData["RootCA"]["rootCAPrivateKey"], "rb") as f_rootCAKeyFile:
        rootCAkeyPEM = serialization.load_pem_private_key(f_rootCAKeyFile.read(), password=None)

    # Sign the certificate based off the Root CA key.
    clientAuthenticationCertificate = clientCertificateBuilder.sign(rootCAkeyPEM, cryptography_support.cryptography_support.generateHash(__certificateMetaData["ClientAuthentication"]["rsa"]["digest"]), default_backend())

    clientPublicKey = clientPrivateKey.public_key()

    # Print the disclaimer.
    printDisclaimer()

    # Client the client private key to file.
    if write_client_private_key(clientPrivateKey, __certificateMetaData["ClientAuthentication"]["clientCertificatePrivateKey"]):
        print(f"Client certificate private key filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePrivateKey']}")
    else:
        print(f"Error when writing client private key to {__certificateMetaData['ClientAuthentication']['clientCertificatePrivateKey']}")
        sys.exit(1)

    # Write the client certificate to file.
    if write_client_public_key(clientPublicKey, __certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']):
        print(f"Client certificate filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']}")
    else:
        print(f"Error when writing client public key to {__certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']}")
        sys.exit(1)

    if args.generatePKCS12:
        # Generate a PKCS12 File for the Client Certificate Authenticate.
        write_client_certificate_pkcs12(__certificateMetaData, clientPrivateKey, clientAuthenticationCertificate)

        if args.windowsInstallation:
            printWindowsInstallationInstructions(__certificateMetaData, newPassphrase)


def main():
    """The main definition."""
    # Parse arguments for the script.
    parseArguments()

    # Check to see if we need to remove all certificates, private keys, and PKCS12 formatted files.
    if args.removeAllCertsAndKeys:
        removeAllCertsAndKeys()
        sys.exit(0)

    # Setup the template for the certificate structure for both Root CA and Client Certificate.
    myCertMetaData = certificateMetaData()

    # Adding logic handling for when only --companyName is passed.
    if args.companyName and not (args.generateRootCA or args.generateClientCertificate):
        print("Missing --generateRootCA or --generateClientCertificate Argument.")
        sys.exit(1)

    # Check to see if Root CA needs to be generated.
    if args.generateRootCA and args.companyName:
        createRootCA(myCertMetaData)

    # Check to see if Client Certificate needs to be generated.
    if args.generateClientCertificate and args.companyName:
        createClientCertificate(myCertMetaData)


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