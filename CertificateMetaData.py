import json
from datetime import datetime, timedelta
import os

class CertificateMetaData:
    """
    A class to manage and generate certificate metadata based on supplied information from JSON files.
    """

    def __init__(self, **kwargs):
        """Initialize the class and attempt to load certificate information."""
        self.company_name = kwargs.get('companyName', 'ACME Corp')
        self.certificate_info = {}

        try:
            self.load_root_ca()
            self.load_client_authentication()
            self.add_not_before_and_after(self.certificate_info["RootCA"])
            self.add_not_before_and_after(self.certificate_info["ClientAuthentication"])

        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading JSON files: {e}")
            exit(1)

    def normalize_name(self, name: str) -> str:
        """
        Normalize the company name to only have numbers, letters, and spaces.

        Args:
            name (str): The company name.

        Returns:
            str: A normalized version of the company name.
        """
        return ''.join(filter(lambda x: x.isalpha() or x.isspace() or x.isdigit(), name))

    def add_not_before_and_after(self, certificate_dict: dict) -> None:
        """
        Add notBefore and notAfter fields to the certificate information.

        Args:
            certificate_dict (dict): The dictionary containing the certificate information.
        """
        certificate_dict["notBefore"] = datetime.today()
        certificate_dict["notAfter"] = datetime.today() + timedelta(seconds=31536000)

    def load_root_ca(self) -> None:
        """Load the Root Certificate Authority information from a JSON file."""
        with open('RootCertificateAuthority.json', 'r') as file:
            self.certificate_info["RootCA"] = json.load(file)

        rootCAFileName = "root-ca-" + self.normalize_name(self.company_name).replace(' ', '-').lower()

        self.certificate_info["RootCA"]["rootCAFileName"] = rootCAFileName
        self.certificate_info["RootCA"]["rootCAPublicKey"] = f"{rootCAFileName}.crt"
        self.certificate_info["RootCA"]["rootCAPrivateKey"] = f"{rootCAFileName}.key"
        self.certificate_info["RootCA"]["rootCAPKCS12"] = f"{rootCAFileName}.p12"

        if self.certificate_info["RootCA"]["oid"]["CN"] is None:
            self.certificate_info["RootCA"]["oid"]["CN"] = f"{self.company_name} + Root CA"

        if self.certificate_info["RootCA"]["oid"]["companyName"] is None:
            self.certificate_info["RootCA"]["oid"]["companyName"] = f"{self.company_name}"

    def load_client_authentication(self) -> None:
        """Load the Client Authentication certificate information from a JSON file."""
        with open('ClientCertificate.json', 'r') as file:
            self.certificate_info["ClientAuthentication"] = json.load(file)

        client_cert_file_name = "client-cert-" + self.normalize_name(self.company_name).replace(' ', '-').lower()
        
        self.certificate_info["ClientAuthentication"]["clientCertificatePublicKey"] = f"{client_cert_file_name}.crt"
        self.certificate_info["ClientAuthentication"]["clientCertificatePrivateKey"] = f"{client_cert_file_name}.key"
        self.certificate_info["ClientAuthentication"]["clientCertificatePKCS12"] = f"{client_cert_file_name}.p12"

