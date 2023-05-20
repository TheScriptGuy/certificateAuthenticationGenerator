# Description:           What types of cryptography are we going to support
# Author:                TheScriptGuy
# Last modified:         2023-05-20
# Version 0.01

from typing import Union
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization

class cryptography_support:
    """What crypto are we supporting within this scrypt."""
    private_key_types = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    public_key_types = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]

    def generateHash(__hash: str) -> hashes:
        """Generate the hashes used for encryption."""
        hashObj = None

        match __hash:
            case "sha224":
                hashObj = hashes.SHA224()
            case "sha256":
                hashObj = hashes.SHA256()
            case "sha384":
                hashObj = hashes.SHA384()
            case "sha512":
                hashObj = hashes.SHA512()
            case "sha512_224":
                hashObj = hashes.SHA512_224()
            case "sha512_256":
                hashObj = hashes.SHA512_256()

        return hashObj


    def generateCurve(__curve: str) -> ec:
        """Generate the appropriate curve."""
        curveObj = None

        match  __curve:
            case "secp256r1":
                curveObj = ec.SECP256R1()
            case "secp384r1":
                curveObj = ec.SECP384R1()
            case "secp521r1":
                curveObj = ec.SECP256R1()
            case "secp224r1":
                curveObj = ec.SECP224R1()
            case "secp192r1":
                curvObj = ec.SECP192R1()

        return curveObj

    def __init__(self):
        """Initialize the class."""
        self.classVersion = "0.01"
        self.initialized = True
