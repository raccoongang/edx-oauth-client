import logging
from typing import Optional

from django.conf import settings
from iit_protection.EUSignCP import EU_CERT_KEY_TYPE_DSTU4145, EU_KEY_USAGE_KEY_AGREEMENT, EUGetInterface, EULoad, EUUnload

log = logging.getLogger(__name__)


class IdGovUaSignLibraryError(Exception):
    """
    Exception raised when id.gov.ua signature library gets an error.
    """


class IdGovUaSignLibrary:
    """
    The class is a wrapper for working with the id.gov.ua library.

    The following functions have been implemented:
     - working with private keys,
     - work with certificates of private keys,
     - directed encryption and decryption of data.
    """

    _instance = None

    def __init__(self, private_key_filepath, private_key_password):
        self.private_key_filepath = private_key_filepath
        self.private_key_password = private_key_password
        self.public_interface = None
        self.private_key_context = None
        self.enveloped_certificate = None

    @classmethod
    def get_initialized_instance(cls) -> "IdGovUaSignLibrary":
        """
        Class method that provides the behavior of a singleton.

        It is important to note that it is almost impossible
        to implement singleton class behavior in the Django framework.
        There will be as many singletons as the application server will launch workers.
        For the current task, this is not a problem.
        The main thing is that the behavior of the singleton class should be at least within of one worker.

        In addition to defining a singleton interface, a class method also performs instance initialization.
        Will be done:
         - id.gov.ua library loading,
         - reading private key,
         - reading certificate of a private key.
        """
        if cls._instance is None:
            exc = None
            cls._instance = cls(
                settings.PRIVATE_KEY_FILE_PATH,
                settings.PRIVATE_KEY_PASSWORD,
            )
            try:
                cls._instance.initialize()
            except Exception as e:
                exc = e
                log.exception('Initializing id.gov.ua signature ligrary failed')
            else:
                log.info('id.gov.ua signature ligrary initialized successfully')

            if not exc and not cls._instance.is_private_key_read():
                try:
                    cls._instance.read_private_key()
                except Exception as e:
                    exc = e
                    error_context = eval(str(e))
                    log.exception(
                        'Private key reading failed. Error code: %s. Description: %s',
                        error_context['ErrorCode'],
                        error_context['ErrorDesc'],
                    )
                else:
                    log.info('Private key read successfully')

            if not exc and not cls._instance.is_certificate_read():
                try:
                    cls._instance.read_certificate()
                except Exception as e:
                    exc = e
                    error_context = eval(str(e))
                    log.exception(
                        'Own certificate by private key reading failed. Error code: %s. Description: %s',
                        error_context['ErrorCode'],
                        error_context['ErrorDesc'],
                    )
                else:
                    log.info('Own certificate read successfully')

            if exc:
                cls._instance.public_interface.Finalize()
                EUUnload()
                raise IdGovUaSignLibraryError(exc)

        return cls._instance

    def initialize(self) -> None:
        """
        Library entry point.

        Initial loading and initialization of interfaces.
        """
        EULoad()
        self.public_interface = EUGetInterface()
        self.public_interface.Initialize()

    def is_private_key_read(self) -> bool:
        """
        Predicate method that defines whether the private key has been read or not.
        """
        return bool(self.private_key_context)

    def is_certificate_read(self) -> bool:
        """
        Predicate method that defines whether the own certificate has been read or not.
        """
        return bool(self.enveloped_certificate)

    def read_private_key(self) -> None:
        """
        Read private key from file.

        Method does not return anything, but saves only context of the key in
        the state of the class instance.
        Method is convenient to use during initialization.
        """
        key_info = None
        self.public_interface.ReadPrivateKeyFile(self.private_key_filepath, self.private_key_password, key_info)
        self.private_key_context = key_info

    def read_certificate(self) -> None:
        """
        Obtaining information about the private key certificate.

        Method does not return anything, but enveloped certificate in
        the state of the class instance.
        Method is convenient to use during initialization.
        """
        cert_info = None
        enveloped_cert = None
        self.public_interface.CtxGetOwnCertificate(
            self.private_key_context,
            EU_CERT_KEY_TYPE_DSTU4145,
            EU_KEY_USAGE_KEY_AGREEMENT,
            cert_info,
            enveloped_cert,
        )
        self.enveloped_certificate = enveloped_cert

    def develop_data(self, base64_enveloped_data: str, bytes_enveloped_data: Optional[bytes] = None) -> str:
        """
        Decryption of data using the context of the private key.

        If a sender's certificate is passed, the sender's encrypted data certificate is not checked in the file store
        and is not written to the file store
        """
        developed_data = None
        self.public_interface.CtxDevelopData(
            self.private_key_context,
            base64_enveloped_data,
            bytes_enveloped_data,
            len(base64_enveloped_data),
            self.enveloped_certificate,
            len(self.enveloped_certificate),
            developed_data,
            pInfo=None,
        )

        return developed_data
