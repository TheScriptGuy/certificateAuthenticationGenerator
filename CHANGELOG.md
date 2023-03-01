# 2022-03-01
## Version 1.02
* Fixed minor issue when normalizing the `--companyName` string.

## Version 1.01
* Optimized the way the hashing works within the code.


# 2022-02-28
## Version 1.00
* Rewrote the code(!) to use python cryptography instead of crypto. 

## Version 0.06
* Amended dict structure to allow for future Elliptic Curve Cryptography (ECC) creations.

## Version 0.05
* Created a more restrictive Root CA by default. Root CA will only be allowed to validate certificates used for Client Authentication.
* Amended the certificate versions for both `Root CA` and `Client Authentication` certificate to be `Version 3`.

## Version 0.04
* Added Root CA certificate to client authentication .p12 file.

## Version 0.03
* Added Windows installation instructions for importing the certificate by using the `--windowsInstallation` argument.


# 2022-02-24
## Version 0.02
* Fixes - adding logic to handle if only `--companyName` argument is passed without anything else.


# 2022-02-22
## Version 0.01
Initial publication of script.
