"""
The moment you've been waiting for: actually getting SSL. For free!
"""

import binascii
import os
import logging

from cryptography.hazmat.primitives.hashes import SHA256

from .acme import Acme
from .errors import ManualeError
from .crypto import (
    generate_rsa_key,
    load_private_key,
    export_private_key,
    create_csr,
    load_csr,
    export_csr_for_acme,
    load_der_certificate,
    export_pem_certificate,
)
from .helpers import confirm

logger = logging.getLogger(__name__)

EXPIRATION_FORMAT = "%Y-%m-%d"

def issue(server, account, domains, key_size, key_file=None, csr_file=None, output_path=None):
    if not output_path or output_path == '.':
        output_path = os.getcwd()

    # Load key if given
    if key_file:
        try:
            with open(key_file, 'rb') as f:
                certificate_key = load_private_key(f.read())
        except (ValueError, AttributeError, TypeError, IOError) as e:
            logger.error("Couldn't read certificate key.")
            raise ManualeError(e)
    else:
        certificate_key = None

    # Load CSR or generate
    if csr_file:
        try:
            with open(csr_file, 'rb') as f:
                csr = export_csr_for_acme(load_csr(f.read()))
        except (ValueError, AttributeError, TypeError, IOError) as e:
            logger.error("Couldn't read CSR.")
            raise ManualeError(e)
    else:
        # Generate key
        if not key_file:
            logger.info("Generating a {} bit RSA key. This might take a second.".format(key_size))
            certificate_key = generate_rsa_key(key_size)
            logger.info("Key generated.")
            logger.info("")

        csr = create_csr(certificate_key, domains)

    acme = Acme(server, account)
    try:
        logger.info("Requesting certificate issuance...")
        result = acme.issue_certificate(csr)
        logger.info("Certificate issued.")
    except IOError as e:
        logger.error("Connection or service request failed. Aborting.")
        raise ManualeError(e)

    try:
        certificate = load_der_certificate(result.certificate)

        # Print some neat info
        logger.info("")
        logger.info("  Expires: {}".format(certificate.not_valid_after.strftime(EXPIRATION_FORMAT)))
        logger.info("   SHA256: {}".format(binascii.hexlify(certificate.fingerprint(SHA256())).decode('ascii')))
        logger.info("")

        # Write the key, certificate and full chain
        os.makedirs(output_path, exist_ok=True)
        cert_path = os.path.join(output_path, domains[0] + '.crt')
        chain_path = os.path.join(output_path, domains[0] + '.chain.crt')
        intermediate_path = os.path.join(output_path, domains[0] + '.intermediate.crt')
        key_path = os.path.join(output_path, domains[0] + '.pem')

        if certificate_key is not None:
            with open(key_path, 'wb') as f:
                os.chmod(key_path, 0o600)
                f.write(export_private_key(certificate_key))
                logger.info("Wrote key to {}".format(f.name))

        with open(cert_path, 'wb') as f:
            f.write(export_pem_certificate(certificate))
            logger.info("Wrote certificate to {}".format(f.name))

        with open(chain_path, 'wb') as f:
            f.write(export_pem_certificate(certificate))
            if result.intermediate:
                f.write(export_pem_certificate(load_der_certificate(result.intermediate)))
            logger.info("Wrote certificate with intermediate to {}".format(f.name))

        if result.intermediate:
            with open(intermediate_path, 'wb') as f:
                f.write(export_pem_certificate(load_der_certificate(result.intermediate)))
                logger.info("Wrote intermediate certificate to {}".format(f.name))
    except IOError as e:
        logger.error("Failed to write certificate or key. Going to print them for you instead.")
        logger.error("")
        if certificate_key is not None:
            for line in export_private_key(certificate_key).decode('ascii').split('\n'):
                logger.error(line)
        for line in export_pem_certificate(certificate).decode('ascii').split('\n'):
            logger.error(line)
        raise ManualeError(e)
