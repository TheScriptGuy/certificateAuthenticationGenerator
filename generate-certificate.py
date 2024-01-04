# Description:     Create a Root CA with a client Authentication certificate that's signed by the Root CA.
# Author:          TheScriptGuy
# Last modified:   2024-01-03
# Version:         1.10

from RootCertificateAuthority import RootCertificateAuthority
from ClientCertificate import ClientCertificate
from CryptographySupport import CryptographyFileOperations
from CertificateMetaData import CertificateMetaData

import sys
import argparse

scriptVersion = "1.10"


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

    # Adding logic handling for when only --companyName is passed.
    if args.companyName and not (args.generateRootCA or args.generateClientCertificate):
        print("Missing --generateRootCA or --generateClientCertificate Argument.")
        sys.exit(1)

    # Setup the template for the certificate structure for both Root CA and Client Certificate.
    myCertMetaData = CertificateMetaData(
            companyName=args.companyName
            )

    # First check to see if only one argument was passed
    # Can only be --dnsName or --userPrincipalName, but not both. Exit if true.
    if args.dnsName and args.userPrincipalName:
        # Print an error message and exit.
        print("Please use either --dnsName or --userPrincipalName, but not both.")
        sys.exit(1)

    # Check to see if Root CA needs to be generated.
    if args.generateRootCA and args.companyName:
        RootCertificateAuthority.create_root_ca(
                myCertMetaData.certificate_info,
                RestrictiveRootCA=bool(args.nonRestrictiveRootCA),
                generatePKCS12=bool(args.generatePKCS12),
                ecc=bool(args.ecc),
                windowsInstallation=bool(args.windowsInstallation)
                )

    # Check to see if Client Certificate needs to be generated.
    if args.generateClientCertificate and args.companyName:
        ClientCertificate.create_client_certificate(
                myCertMetaData.certificate_info,
                ecc=bool(args.ecc),
                generatePKCS12=bool(args.generatePKCS12),
                dnsName=bool(args.dnsName),
                userPrincipalName=bool(args.userPrincipalName),
                windowsInstallation=bool(args.windowsInstallation)
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
