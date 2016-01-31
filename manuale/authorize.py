"""
The domain authorization command. Authorizations last up to 300 days on the
production Let's Encrypt service at the time of writing, so it makes sense to
separate certificate issuance from ownership verification.

TODO: Authorizing multiple domains at the same time once the ACME API
supports finding existing authorizations, complete or pending. Until then, it
would be too easy to lock yourself out because of strict rate limits.
"""

import logging
import time
import hashlib

from .acme import Acme
from .crypto import generate_jwk_thumbprint, jose_b64
from .errors import ManualeError, AcmeError
from .helpers import confirm

logger = logging.getLogger(__name__)

def authorize(server, account, domain):
    acme = Acme(server, account)
    thumbprint = generate_jwk_thumbprint(account.key)

    try:
        logger.info("Requesting challenge for {}.".format(domain))
        authorization = acme.new_authorization(domain)

        # Find the dns-01 challenge.
        challenge = None
        for ch in authorization.contents.get('challenges', []):
            if ch['type'] == 'dns-01':
                challenge = ch
                break
        if not challenge:
            logger.error("Manuale only supports the DNS-01 challenge. The server did not return one.")
            raise ManualeError()

        # Build key authorization and DNS token value.
        keyauth = "{}.{}".format(challenge['token'], thumbprint)
        hash = hashlib.sha256()
        hash.update(keyauth.encode('ascii'))
        txt = jose_b64(hash.digest())

        # Print instructions and wait.
        logger.info("DNS verification required. Make sure this TXT record is in place:")
        logger.info("  _acme-challenge.{}. \"{}\"".format(domain, txt))
        logger.info("(Give it a minute or two.)")
        input("Press enter to continue.")

        # Submit challenge and poll.
        acme.validate_authorization(challenge['uri'], 'dns-01', keyauth)
        while True:
            logger.info("Waiting for verification. Sleeping for 5 seconds.")
            time.sleep(5)

            response = acme.get_authorization(authorization.uri)
            status = response.get('status')
            if status == 'valid':
                logger.info("{} verified! According to the server, this authorization lasts until {}.".format(domain, response.get('expires', '(not provided)')))
                logger.info("Let's Encrypt!")
                break
            elif status != 'pending':
                logger.error("Verification failed with status '{}'. Aborting.".format(status))
                raise ManualeError()
    except IOError as e:
        logger.error("A connection or service error occurred. Aborting.")
        raise ManualeError(e)
