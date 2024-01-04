import random

from CryptographySupport import CryptographySupport, CryptographyFileOperations
from UserFeedback import UserFeedback

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509


class RootCertificateAuthority:
    """This class is used for Root Certificate Authority Operations."""
    CLASS_VERSION = "0.01"
    AUTHOR = "TheScriptGuy"
    LAST_MODIFIED = "2024-01-03"

    @staticmethod
    def create_root_private_keys(__certificateMetaData: dict, **kwargs) -> CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES:
        """Create a private key."""
        # First check to see if the --ecc argument was passed. If passed, generate ECC key.
        if 'ecc' in kwargs and kwargs['ecc']:
            UserFeedback.print_line('Using Elliptic Curve for Root Certificate Authority.')
            __private_key = ec.generate_private_key(
                curve=CryptographySupport.CryptographySupport.generate_curve(__certificateMetaData["RootCA"]["ecc"]["curve"]),
                backend=default_backend()
            )
        else:
            UserFeedback.print_line('Using RSA for Root Certificate Authority.')
            __private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=__certificateMetaData["RootCA"]["rsa"]["rsa_bits"],
                backend=default_backend()
            )
        return __private_key

    @staticmethod
    def create_root_ca(__certificateMetaData: dict, **kwargs) -> None:
        """Create a Root CA with the information from the --companyName argument."""
        rootCAPrivateKey = RootCertificateAuthority.create_root_private_keys(__certificateMetaData, **kwargs)

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
        if 'RestrictiveRootCA' in kwargs and kwargs['RestrictiveRootCA']:
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
        else:
            UserFeedback.print_line("Non restrictive Root Certificate Authority defined.")

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
        UserFeedback.print_disclaimer()

        # Write private key to file
        if CryptographyFileOperations.CryptographyFileOperations.write_private_key_to_file(rootCAPrivateKey, __certificateMetaData['RootCA']['rootCAPrivateKey']):
            UserFeedback.print_line(f"Root CA private key filename - {__certificateMetaData['RootCA']['rootCAPrivateKey']}")
        else:
            UserFeedback.print_line(f"Error writing to file {__certificateMetaData['RootCA']['rootCAPrivateKey']}")
            sys.exit(1)

        # Write the public key to file.
        if CryptographyFileOperations.CryptographyFileOperations.write_public_key_to_file(rootCACertificate, __certificateMetaData["RootCA"]["rootCAPublicKey"]):
            UserFeedback.print_line(f"Root CA certificate filename - {__certificateMetaData['RootCA']['rootCAPublicKey']}")
        else:
            UserFeedback.print_line(f"Error writing to file {__certificateMetaData['RootCA']['rootCAPublicKey']}")
            sys.exit(1)

        if 'generatePKCS12' in kwargs and kwargs['generatePKCS12']:
            # Generate a PKCS12 file for the Root CA.
            root_ca_passphrase = CryptographyFileOperations.CryptographyFileOperations.write_rootca_pkcs12(
                __certificateMetaData,
                rootCAPrivateKey,
                rootCACertificate
            )
            if root_ca_passphrase:
                UserFeedback.print_line(f"Password for {__certificateMetaData['RootCA']['rootCAPKCS12']} is {root_ca_passphrase}")

                if 'windows_installation' in kwargs and kwargs['windows_installation']:
                    UserFeedback.print_windows_installation_instructions(__certificateMetaData, root_ca_passphrase)

        UserFeedback.print_line()
