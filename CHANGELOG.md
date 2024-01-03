# 2024-01-03
## Version 1.09
* Making the code more modular and aligning with better coding practices.

# 2023-08-02
## Version 1.08
* Adding enhancement for [Subject Alternative Names](https://github.com/TheScriptGuy/certificateAuthenticationGenerator/issues/8)
* Inadvertently identifying (and now fixed) a flaw in my Client Certificate Authentication generator.

# 2023-05-31
## Version 1.07
* Adjusting code to align with better coding practices.

# 2023-05-21
## Version 1.06
* Adjusting code to align with better coding practices.

# 2023-05-20
## Version 1.05
* Adjusting code to be more classy!

## Version 1.04
* Code changes to align with PEP 8 recommendations - Part 1(?)

# 2023-03-01
## Version 1.03
* Added support for elliptic curve encryption.

## Version 1.02
* Fixed minor issue when normalizing the `--companyName` string.

## Version 1.01
* Optimized the way the hashing works within the code.


# 2023-02-28
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


# 2023-02-24
## Version 0.02
* Fixes - adding logic to handle if only `--companyName` argument is passed without anything else.


# 2023-02-22
## Version 0.01
Initial publication of script.
