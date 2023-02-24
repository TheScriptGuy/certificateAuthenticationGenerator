# Formats the json output to get all the egress IPs
# Author:          TheScriptGuy
# Last modified:   2023-02-22
# Version:         0.01
# Description:     Create a Root CA with a client Authentication certificate that's signed by the Root CA.
from OpenSSL import crypto, SSL
from os.path import join
import random
import sys
import os
import argparse
import glob

scriptVersion = "0.01"


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

    parser.add_argument('--removeAllCertsAndKeys', action='store_true',
                        help='Removes all files matching wildcard *.crt, *.key, *.p12. USE WITH CAUTION.')


    global args
    args = parser.parse_args()

def certificateMetaData():
    """Generate certificate structure based on supplied information."""
    certificateInfo = {}

    normalizedName = ''.join(filter(lambda x: x.isalpha() or x.isspace(),args.companyName))

    rootCAFileName = "root-ca-" + normalizedName.replace(' ', '-').lower()

    clientCertificateFileName = "client-cert-" + normalizedName.replace(' ', '-').lower()

    certificateInfo["RootCA"] = {
        "CN": args.companyName + " Root CA",
        "companyName": args.companyName, 
        "organizationalUnit": "Client Authentication CA",
        "rootCAFileName": rootCAFileName,
        "rootCAPublicKey": f"{rootCAFileName}.crt",
        "rootCAPrivateKey": f"{rootCAFileName}.key",
        "rootCAPKCS12": f"{rootCAFileName}.p12",
        "notBefore": 0,
        "notAfter": 31536000,
        "rsa_bits": 2048,
        "digest": "sha512",
    }

    certificateInfo["ClientAuthentication"] = {
        "CN": "Endpoint Client Authentication",
        "organizationalUnit": "Client Authentication",
        "clientCertificatePublicKey": f"{clientCertificateFileName}.crt",
        "clientCertificatePrivateKey": f"{clientCertificateFileName}.key",
        "clientCertificatePKCS12": f"{clientCertificateFileName}.p12",
        "rsa_bits": 2048,
        "digest": "sha256",
        "notBefore": 0,
        "notAfter": 31536000,
        "extensions": {
            "keyUsage": "digitalSignature, nonRepudiation",
            "extendedKeyUsage": "clientAuth"
        }
    }

    return certificateInfo


def generatePassphrase(__passwordLength):
    """Generate a random password based on the length supplied."""
    validLetters = "abcdefghijklmnopqrstuvwxyz"
    validNumbers = "0123456789"

    validCharacters = validLetters + validNumbers

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
    print("----------------------------------------------------------------------------")
    print("DISCLAIMER:")
    print("These files are not meant for production environments. Use at your own risk.")
    print("----------------------------------------------------------------------------")


def createRootCA(__certificateMetaData):
    """Create a Root CA with the information from the --companyName argument."""
    rootCAPrivateKey = crypto.PKey()
    rootCAPrivateKey.generate_key(crypto.TYPE_RSA, __certificateMetaData["RootCA"]["rsa_bits"])

    # Generate a random serial number
    rootSerialNumber = random.getrandbits(64)

    # create a self-signed cert
    rootCAcert = crypto.X509()
    rootCAcert.get_subject().O = __certificateMetaData["RootCA"]["companyName"]
    rootCAcert.get_subject().OU = __certificateMetaData["RootCA"]["organizationalUnit"]
    rootCAcert.get_subject().CN = __certificateMetaData["RootCA"]["CN"]
    rootCAcert.set_serial_number(rootSerialNumber)
    rootCAcert.gmtime_adj_notBefore(__certificateMetaData["RootCA"]["notBefore"])
    rootCAcert.gmtime_adj_notAfter(__certificateMetaData["RootCA"]["notAfter"])
    rootCAcert.set_issuer(rootCAcert.get_subject())
    rootCAcert.set_pubkey(rootCAPrivateKey)
    rootCAcert.sign(rootCAPrivateKey, __certificateMetaData["RootCA"]["digest"])

    # Dump the public certificate
    publicRootCACertPEM = crypto.dump_certificate(crypto.FILETYPE_PEM, rootCAcert)
    privateRootCAKeyPEM = crypto.dump_privatekey(crypto.FILETYPE_PEM, rootCAPrivateKey)

    # Print the Disclaimer
    printDisclaimer()

    # Write the public key to file.
    open(__certificateMetaData["RootCA"]["rootCAPublicKey"],"wt").write(publicRootCACertPEM.decode("utf-8"))
    print(f"Root CA certificate filename - {__certificateMetaData['RootCA']['rootCAPublicKey']}")

    # Write the private key to file.
    open(__certificateMetaData["RootCA"]["rootCAPrivateKey"], "wt").write(privateRootCAKeyPEM.decode("utf-8") )
    print(f"Root CA private key filename - {__certificateMetaData['RootCA']['rootCAPrivateKey']}")

    if args.generatePKCS12:
        # Generate a PKCS12 file for the Root CA.
        rootCAPKCS12 =  crypto.PKCS12()
        rootCAPKCS12.set_privatekey(rootCAPrivateKey)
        rootCAPKCS12.set_certificate(rootCAcert)

        newPassphrase = generatePassphrase(30)

        rootCAPKCS12output = rootCAPKCS12.export(newPassphrase.encode("ascii"))

        with open(__certificateMetaData['RootCA']['rootCAPKCS12'], 'wb') as rootCAPKCS12file:
            rootCAPKCS12file.write(rootCAPKCS12output)

        print(f"Password for {__certificateMetaData['RootCA']['rootCAPKCS12']} is {newPassphrase}")

def checkRootCAFilesExist(__certificateMetaData):
    """
    This will check to see if the root CA public and private key exist.
    If not, exit with system code 1.
    """
    if not (os.path.isfile(__certificateMetaData["RootCA"]["rootCAPublicKey"]) and os.path.isfile(__certificateMetaData["RootCA"]["rootCAPrivateKey"])):
        print("Root CA public key and private key do not exist.")
        print("Exiting.")
        sys.exit(1)

def createClientCertificate(__certificateMetaData):
    """Create the client certificate and sign it from the root CA created from createRootCA()"""
    checkRootCAFilesExist(__certificateMetaData)

    # Generate the private key for the client authenticate certificate.
    clientCertificateKey = crypto.PKey()
    clientCertificateKey.generate_key(crypto.TYPE_RSA, __certificateMetaData["ClientAuthentication"]["rsa_bits"])
    clientCertificateKeyPEM = crypto.dump_privatekey(crypto.FILETYPE_PEM, clientCertificateKey)

    # Print the disclaimer.
    printDisclaimer()

    # Output the private key to file.
    open(__certificateMetaData["ClientAuthentication"]["clientCertificatePrivateKey"],"wt").write(clientCertificateKeyPEM.decode("utf-8"))
    print(f"Client certificate private key filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePrivateKey']}")

    # Create the Certificate Signing Request
    clientCsr = crypto.X509Req()
    clientCsr.get_subject().O = __certificateMetaData["RootCA"]["companyName"]
    clientCsr.get_subject().OU = __certificateMetaData["ClientAuthentication"]["organizationalUnit"]
    clientCsr.get_subject().CN = __certificateMetaData["ClientAuthentication"]["CN"]
    clientCsr.set_pubkey(clientCertificateKey)



    with open(__certificateMetaData["RootCA"]["rootCAPublicKey"]) as rootCACertFile:
        rootCAcertPEM = rootCACertFile.read()
        rootCAcert = crypto.load_certificate(crypto.FILETYPE_PEM, rootCAcertPEM)

    with open(__certificateMetaData["RootCA"]["rootCAPrivateKey"]) as rootCAKeyFile:
        rootCAkeyPEM = rootCAKeyFile.read()
        rootCAkey = crypto.load_privatekey(crypto.FILETYPE_PEM, rootCAkeyPEM)

    # Now create the Certificate
    clientCertificate = crypto.X509()
    clientCertificate.set_serial_number(random.getrandbits(64))
    clientCertificate.gmtime_adj_notBefore(__certificateMetaData["ClientAuthentication"]["notBefore"])
    clientCertificate.gmtime_adj_notAfter(__certificateMetaData["ClientAuthentication"]["notAfter"])
    clientCertificate.set_issuer(rootCAcert.get_subject())
    clientCertificate.set_subject(clientCsr.get_subject())
    clientCertificate.set_pubkey(clientCsr.get_pubkey())

    # Add extensions to certificate
    clientExtensions = [
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", __certificateMetaData["ClientAuthentication"]["extensions"]["keyUsage"], __certificateMetaData["ClientAuthentication"]["extensions"]["keyUsage"].encode('ascii')),
        crypto.X509Extension(b"extendedKeyUsage", True, __certificateMetaData["ClientAuthentication"]["extensions"]["extendedKeyUsage"].encode('ascii'))
    ]
    clientCertificate.add_extensions(clientExtensions)

    clientCertificate.sign(rootCAkey, __certificateMetaData["ClientAuthentication"]["digest"])

    clientCertificateFile = crypto.dump_certificate(crypto.FILETYPE_PEM, clientCertificate)


    # Write the public key to file.
    open(__certificateMetaData["ClientAuthentication"]["clientCertificatePublicKey"],"wt").write(clientCertificateFile.decode("utf-8"))
    print(f"Client certificate public key filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']}")

    if args.generatePKCS12:
        # Generate a PKCS12 File for the Client Certificate Authenticate.
        clientCertificatePKCS12 =  crypto.PKCS12()
        clientCertificatePKCS12.set_privatekey(clientCertificateKey)
        clientCertificatePKCS12.set_certificate(clientCertificate)

        newPassphrase = generatePassphrase(10)

        clientCertificatePKCS12output = clientCertificatePKCS12.export(newPassphrase.encode("ascii"))

        with open(__certificateMetaData['ClientAuthentication']['clientCertificatePKCS12'], 'wb') as clientCertificatePKCS12file:
            clientCertificatePKCS12file.write(clientCertificatePKCS12output)

        print(f"Password for {__certificateMetaData['ClientAuthentication']['clientCertificatePKCS12']} is {newPassphrase}")

def main():
    """The main definition."""
    # Parse arguments for the script.
    parseArguments()

    if args.removeAllCertsAndKeys:
        removeAllCertsAndKeys()
        sys.exit(0)

    myCertMetaData = certificateMetaData()

    if args.generateRootCA and args.companyName:
        createRootCA(myCertMetaData)

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
