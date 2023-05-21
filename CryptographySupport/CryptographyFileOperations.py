# Description:           Supported cryptography file operations
# Author:                TheScriptGuy
# Last modified:         2023-05-20
# Version:               0.01

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from CryptographySupport import CryptographySupport

from os.path import join

import glob
import os
import random


class CryptographyFileOperations:
    """This class is used for all of the file components for private and public key handling."""

    CLASS_VERSION = 0.01

    @staticmethod
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

    @staticmethod
    def remove_all_certs_and_keys():
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

    @staticmethod
    def write_private_key_to_file(
            __private_key: CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES,
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
        except PermissionError:
            print("You don't have the permissions to write to this file.")
            successful_write = False
        except IsADirectoryError:
            print("The specified path is a directory, not a file.")
            successful_write = False
        except IOError as e:
            print(f"An I/O error occurred: {e}")
            successful_write = False

        return successful_write

    @staticmethod
    def write_public_key_to_file(
            __public_key: CryptographySupport.CryptographySupport.PUBLIC_KEY_TYPES,
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
        except PermissionError:
            print("You don't have the permissions to write to this file.")
            successful_write = False
        except IsADirectoryError:
            print("The specified path is a directory, not a file.")
            successful_write = False
        except IOError as e:
            print(f"An I/O error occurred: {e}")
            successful_write = False

        return successful_write

    @staticmethod
    def write_rootca_pkcs12(
            __certificateMetaData: dict,
            __rootCAPrivateKey: CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES,
            __rootCACertificate: x509.Certificate
            ) -> str:
        """Combine both the __rootCAPrivateKey and __rootCACertificate into pkcs12 file format."""
        # Create new 30 character passphrase for the Root CA.
        newPassphrase = CryptographyFileOperations.generatePassphrase(30)

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

        return newPassphrase

    @staticmethod
    def write_client_certificate_pkcs12(
        __certificateMetaData: dict,
        __clientPrivateKey: CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES,
        __clientAuthenticationCertificate: x509.Certificate
    ) -> str:
        """Write the client certificate and Root CA into the PKCS12 file."""
        # Get the Root CA certificate file
        with open(__certificateMetaData["RootCA"]["rootCAPublicKey"], "rb") as f_rootCAKeyFile:
            rootCAPublicKeyPEM = x509.load_pem_x509_certificate(f_rootCAKeyFile.read())

        # Create new 30 character passphrase for the Root CA.
        newPassphrase = CryptographyFileOperations.generatePassphrase(10)

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

        return newPassphrase

    @staticmethod
    def write_client_private_key(
            __private_key: CryptographySupport.CryptographySupport.PRIVATE_KEY_TYPES,
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
        except PermissionError:
            print("You don't have the permissions to write to this file.")
            successful_write = False
        except IsADirectoryError:
            print("The specified path is a directory, not a file.")
            successful_write = False
        except IOError as e:
            print(f"An I/O error occurred: {e}")
            successful_write = False

        return successful_write

    @staticmethod
    def write_client_public_key(
            __public_key: CryptographySupport.CryptographySupport.PUBLIC_KEY_TYPES,
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
        except PermissionError:
            print("You don't have the permissions to write to this file.")
            successful_write = False
        except IsADirectoryError:
            print("The specified path is a directory, not a file.")
            successful_write = False
        except IOError as e:
            print(f"An I/O error occurred: {e}")
            successful_write = False

        return successful_write

    def __init__(self):
        self.initialized = True
