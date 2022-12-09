import logging
from typing import Optional

from django.conf import settings
from django.utils.functional import cached_property
from functools import wraps
from iit_protection.EUSignCP import (
    EU_CERT_KEY_TYPE_DSTU4145,
    EU_KEY_USAGE_KEY_AGREEMENT,
    EUGetInterface,
    EULoad,
    EUUnload,
)

log = logging.getLogger(__name__)


class IdGovUaSignLibraryError(Exception):
    """
    Exception raised when id.gov.ua signature library gets an error.
    """


def library_exception_handler(func):
    """
    Class method decorator for handling id.gov.ua signature library errors.

    Performs soft termination and unloading of the library on error.
    """

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            result = func(self, *args, **kwargs)
        except Exception as exc:
            error_context = eval(str(exc))
            log.exception(
                '%s got error. Error code: %d. Description: %s',
                func.__name__,
                error_context['ErrorCode'],
                error_context['ErrorDesc'],
            )
            self.public_interface.Finalize()
            EUUnload()
            raise IdGovUaSignLibraryError from exc
        else:
            return result

    return wrapper


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

    @classmethod
    def get_instance(cls) -> "IdGovUaSignLibrary":
        """
        Class method that provides the behavior of a singleton.

        It is important to note that it is almost impossible
        to implement singleton class behavior in the Django framework.
        There will be as many singletons as the application server will launch workers.
        For the current task, this is not a problem.
        The main thing is that the behavior of the singleton class should be at least within of one worker.

        In addition to defining a singleton interface, a class method also performs instance initialization.
        Will be done:
         - id.gov.ua library loading.
        """
        if cls._instance is None:
            cls._instance = cls(
                settings.PRIVATE_KEY_FILE_PATH,
                settings.PRIVATE_KEY_PASSWORD,
            )
            cls._instance.initialize()

        return cls._instance

    @library_exception_handler
    def initialize(self):
        """
        Library entry point.

        Initial loading and initialization of interfaces.
        """
        EULoad()
        self.public_interface = EUGetInterface()
        self.public_interface.Initialize()
        log.info('id.gov.ua signature ligrary initialized successfully')

    @cached_property
    @library_exception_handler
    def lib_context(self):
        """
        Creating id.gov.ua signature library context.
        """
        library_context = []
        self.public_interface.CtxCreate(library_context)
        log.info('Sign ligrary context created successfully')
        return library_context[0] if library_context else None

    @cached_property
    @library_exception_handler
    def private_key_context(self):
        """
        Read private key from file.

        Method does not return anything, but saves only context of the key in
        the state of the class instance.
        Method is convenient to use during initialization.
        """
        with open(settings.PRIVATE_KEY_FILE_PATH, 'rb') as f:
            private_key = f.read()

        private_key_context = []
        key_info = {}
        self.public_interface.CtxReadPrivateKeyBinary(
            self.lib_context,
            private_key,
            len(private_key),
            self.private_key_password,
            private_key_context,
            key_info,
        )
        log.info('Key private context read successfully')

        return private_key_context[0] if private_key_context else None

    @cached_property
    @library_exception_handler
    def enveloped_certificate(self):
        """
        Obtaining information about the private key certificate.

        Method does not return anything, but enveloped certificate in
        the state of the class instance.
        Method is convenient to use during initialization.
        """
        cert_info = {}
        enveloped_cert = []
        self.public_interface.CtxGetOwnCertificate(
            self.private_key_context,
            EU_CERT_KEY_TYPE_DSTU4145,
            EU_KEY_USAGE_KEY_AGREEMENT,
            cert_info,
            enveloped_cert,
        )
        log.info('Own certificate read successfully')

        return enveloped_cert[0] if enveloped_cert else None

    @library_exception_handler
    def develop_data(self, base64_enveloped_data: str, bytes_enveloped_data: Optional[bytes] = None) -> str:
        """
        Decryption of data using the context of the private key.

        If a sender's certificate is passed, the sender's encrypted data certificate
        is not checked in the file store and is not written to the file store
        """
        developed_data = []
        info = {}
        self.public_interface.CtxDevelopData(
            self.private_key_context,
            base64_enveloped_data,
            bytes_enveloped_data,
            len(base64_enveloped_data),
            self.enveloped_certificate,
            len(self.enveloped_certificate),
            developed_data,
            pInfo=info,
        )

        return developed_data[0] if developed_data else None
