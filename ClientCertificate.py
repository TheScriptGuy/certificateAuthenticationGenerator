import idna
import random
import os
import sys

from CryptographySupport import CryptographySupport, CryptographyFileOperations
from cryptography import x509

from pyasn1.type import char
from pyasn1.codec.der import encoder as der_encoder

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from UserFeedback import UserFeedback

class ClientCertificate:
    """A class used for creating client certificates."""
    CLASS_VERSION = "0.01"
    AUTHOR = "TheScriptGuy"
    LAST_MODIFIED = "2024-01-03"

    def check_root_ca_files_exist(__certificateMetaData: dict) -> None:
        """
        This will check to see if the root CA public and private key exist.
        If not, exit with system code 1.
        """
        if not (os.path.isfile(__certificateMetaData["RootCA"]["rootCAPublicKey"]) and os.path.isfile(__certificateMetaData["RootCA"]["rootCAPrivateKey"])):
            print("Root CA public key and private key do not exist. Use the --generateRootCA argument to create a Root CA")
            print("Exiting.")
            sys.exit(1)

    def create_client_private_keys(__certificateMetaData: dict, **kwargs) -> CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES:
        """Create a private key."""
        # First check to see if the --ecc argument was passed. If passed, generate ECC key.
        if 'ecc' in kwargs and kwargs['ecc']:
            UserFeedback.print_line('Using Elliptic Curve for Client Certificates')
            __private_key = ec.generate_private_key(
                curve=CryptographySupport.CryptographySupport.generate_curve(__certificateMetaData["ClientAuthentication"]["ecc"]["curve"]),
                backend=default_backend()
            )
        else:
            UserFeedback.print_line('Using RSA for Client Certificates')
            __private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=__certificateMetaData["ClientAuthentication"]["rsa"]["rsa_bits"],
                backend=default_backend()
            )
        return __private_key

    def create_client_certificate(__certificateMetaData: dict, **kwargs) -> None:
        """Create the client certificate and sign it from the root CA created from createRootCA()"""
        ClientCertificate.check_root_ca_files_exist(__certificateMetaData)

        clientPrivateKey = ClientCertificate.create_client_private_keys(__certificateMetaData, **kwargs)

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
        if 'dnsName' in kwargs and kwargs['dnsName']:
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
                UserFeedback.print_line("The required key: value pair was not set for DNSName.")
                sys.exit(1)

        if 'userPrincipalName' in kwargs and kwargs['userPrincipalName']:
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
                UserFeedback.print_line("The required key: value pair was not set for userPrincipalName.")
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
        UserFeedback.print_disclaimer()

        # Client the client private key to file.
        if CryptographyFileOperations.CryptographyFileOperations.write_client_private_key(clientPrivateKey, __certificateMetaData["ClientAuthentication"]["clientCertificatePrivateKey"]):
            UserFeedback.print_line(f"Client certificate private key filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePrivateKey']}")
        else:
            UserFeedback.print_line(f"Error when writing client private key to {__certificateMetaData['ClientAuthentication']['clientCertificatePrivateKey']}")
            sys.exit(1)

        # Write the client certificate to file.
        if CryptographyFileOperations.CryptographyFileOperations.write_client_public_key(clientPublicKey, __certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']):
            UserFeedback.print_line(f"Client certificate filename - {__certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']}")
        else:
            UserFeedback.print_line(f"Error when writing client public key to {__certificateMetaData['ClientAuthentication']['clientCertificatePublicKey']}")
            sys.exit(1)

        if 'generatePKCS12' in kwargs and kwargs['generatePKCS12']:
            # Generate a PKCS12 File for the Client Certificate Authenticate.
            client_certificate_passphrase = CryptographyFileOperations.CryptographyFileOperations.write_client_certificate_pkcs12(
                __certificateMetaData,
                clientPrivateKey,
                clientAuthenticationCertificate
            )
            if client_certificate_passphrase:
                UserFeedback.print_line(f"Password for {__certificateMetaData['ClientAuthentication']['clientCertificatePKCS12']} is {client_certificate_passphrase}")

            if 'windowsInstallation' in kwargs and kwargs['windowsInstallation']:
                UserFeedback.print_windows_installation_instructions(__certificateMetaData, client_certificate_passphrase) 
