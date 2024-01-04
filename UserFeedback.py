class UserFeedback:
    """A class for providing output to stdout."""
    CLASS_VERSION = "0.01"
    header = "-" * 76

    def print_line(line: str = "") -> None:
        """Prints a line to stdout. This is used by other modules."""
        print(line)

    @staticmethod
    def print_disclaimer():
        """Disclaimer for using the certificates."""
        print(UserFeedback.header)
        print("DISCLAIMER:")
        print("These files are not meant for production environments. Use at your own risk.")
        print(UserFeedback.header)

    @staticmethod
    def print_windows_installation_instructions(
        __certificateInfo: dict,
        __p12Password: str
            ) -> None:
        """Display the installation instructions for Windows."""
        print(UserFeedback.header)
        print("Windows Installation (from the directory where files are stored):")
        print("To install Client Authentication certificate into User certificate store (in both cases, click yes to install Root CA as well):")
        print(f"C:\\>certutil -importpfx -f -user -p {__p12Password} {__certificateInfo['ClientAuthentication']['clientCertificatePKCS12']} NoExport")
        print()
        print("To install certificate into Local Machine certificate store:")
        print(f"C:\\>certutil -importpfx -f -Enterprise -p {__p12Password} {__certificateInfo['ClientAuthentication']['clientCertificatePKCS12']} NoExport")

