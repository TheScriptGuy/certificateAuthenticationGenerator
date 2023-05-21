# Description:           Cryptography support
# Author:                TheScriptGuy
# Last modified:         2023-05-20
# Version:               0.01

from typing import Union
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509


class CryptographySupport:
    """What crypto are we supporting within this script."""

    PRIVATE_KEY_TYPES = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    PUBLIC_KEY_TYPES = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
    CLASS_VERSION = "0.01"

    @staticmethod
    def generate_hash(__hash: str) -> hashes.HashAlgorithm:
        """
        Generate the hashes used for encryption.

        Given a hash name as a string, return an instance of the corresponding hash algorithm.
        """
        hash_obj = None

        match __hash:
            case "sha224":
                hash_obj = hashes.SHA224()
            case "sha256":
                hash_obj = hashes.SHA256()
            case "sha384":
                hash_obj = hashes.SHA384()
            case "sha512":
                hash_obj = hashes.SHA512()
            case "sha512_224":
                hash_obj = hashes.SHA512_224()
            case "sha512_256":
                hash_obj = hashes.SHA512_256()

        if hash_obj is None:
            raise ValueError(f"Invalid hash algorithm: {__hash}")

        return hash_obj

    @staticmethod
    def generate_curve(__curve: str) -> ec.EllipticCurve:
        """
        Generate the appropriate curve.

        Given a curve name as a string, return an instance of the corresponding curve.
        """
        curve_obj = None

        match __curve:
            case "secp256r1":
                curve_obj = ec.SECP256R1()
            case "secp384r1":
                curve_obj = ec.SECP384R1()
            case "secp521r1":
                curve_obj = ec.SECP521R1()
            case "secp224r1":
                curve_obj = ec.SECP224R1()
            case "secp192r1":
                curve_obj = ec.SECP192R1()

        if curve_obj is None:
            raise ValueError(f"Invalid curve name: {__curve}")

        return curve_obj

    @staticmethod
    def build_name_attribute(certificateAttributes: dict) -> list:
        """Build a list of all the x509 named attributes in the supplied dict."""
        # Mapping for OID names to their respective OIDs
        oid_mapping = {
            "CN": NameOID.COMMON_NAME,
            "companyName": NameOID.ORGANIZATION_NAME,
            "organizationalUnit": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "locality": NameOID.LOCALITY_NAME,
            "stateOrProvince": NameOID.STATE_OR_PROVINCE_NAME,
            "countryName": NameOID.COUNTRY_NAME,
            "domainComponent": NameOID.DOMAIN_COMPONENT
        }

        name_attribute_list = []

        for item, value in certificateAttributes['oid'].items():
            if value is None:
                continue
            elif item == "domainComponent" and value != [None]:
                for dc in value:
                    name_attribute_list.append(x509.NameAttribute(oid_mapping[item], dc))
            elif item in oid_mapping and item != "domainComponent":
                name_attribute_list.append(x509.NameAttribute(oid_mapping[item], value))

        return name_attribute_list

    def __init__(self):
        """Initialize the class."""
        self.initialized = True
