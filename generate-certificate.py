# Description:     Create a Root CA with a client Authentication certificate that's signed by the Root CA.
# Author:          TheScriptGuy
# Last modified:   2024-01-03
# Version:         1.09

from RootCertificateAuthority import RootCertificateAuthority
from ClientCertificate import ClientCertificate
from CryptographySupport import CryptographyFileOperations

import datetime

import sys
import argparse

scriptVersion = "1.09"

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
            "domainComponent": [None],
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
            "digest": "sha512",
        },
        "extensions": {
            "keyUsage": ["digitalSignature", "nonRepudiation", "keyCertSign"],
            "extendedKeyUsage": ["clientAuth"],
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
            }
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
            "digest": "sha256",
        },
        "extensions": {
            "keyUsage": ["digitalSignature", "nonRepudiation"],
            "extendedKeyUsage": ["clientAuth"],
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
    if args.companyName and not (args.generateRootCA or args.generateClientCertificate):
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
        RootCertificateAuthority.create_root_ca(
                myCertMetaData,
                RestrictiveRootCA = True if not args.nonRestrictiveRootCA else False,
                generatePKCS12 = True if args.generatePKCS12 else False,
                ecc = True if args.ecc else False,
                windowsInstallation = True if args.windowsInstallation else False
                )

    # Check to see if Client Certificate needs to be generated.
    if args.generateClientCertificate and args.companyName:
        ClientCertificate.create_client_certificate(
                myCertMetaData,
                ecc = True if args.ecc else False,
                generatePKCS12 = True if args.generatePKCS12 else False,
                dnsName = True if args.dnsName else False,
                userPrincipalName = True if args.userPrincipalName else False,
                windowsInstallation = True if args.windowsInstallation else False
                )

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
