"""
The certificate revocation command.
"""

import logging

from .acme import Acme
from .errors import ManualeError
from .crypto import (
    load_pem_certificate,
    export_certificate_for_acme,
    get_certificate_domains
)
from .helpers import confirm

logger = logging.getLogger(__name__)

def revoke(server, account, certificate):
    # Load the certificate
    try:
        with open(certificate, 'rb') as f:
            certificate = load_pem_certificate(f.read())
    except IOError as e:
        logger.error("Couldn't read the certificate.")
        raise ManualeError(e)

    # Confirm
    logger.info("Are you sure you want to revoke this certificate? It includes the following domains:")
    for domain in get_certificate_domains(certificate):
        logger.info("  {}".format(domain))
    if not confirm("This can't be undone. Confirm?", default=False):
        raise ManualeError("Aborting.")

    # Revoke.
    acme = Acme(server, account)
    try:
        acme.revoke_certificate(export_certificate_for_acme(certificate))
    except IOError as e:
        raise ManualeError(e)

    logger.info("Certificate revoked.")
