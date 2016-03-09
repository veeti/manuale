"""
The domain authorization command. Authorizations last up to 300 days on the
production Let's Encrypt service at the time of writing, so it makes sense to
separate certificate issuance from ownership verification.
"""

import logging
import time
import hashlib

from .acme import Acme
from .crypto import generate_jwk_thumbprint, jose_b64
from .errors import ManualeError, AcmeError
from .helpers import confirm

logger = logging.getLogger(__name__)

def authorize(server, account, domains):
    acme = Acme(server, account)
    thumbprint = generate_jwk_thumbprint(account.key)

    try:
        # Get pending authorizations for each domain
        authz = {}
        for domain in domains:
            logger.info("Requesting challenge for {}.".format(domain))
            created = acme.new_authorization(domain)
            auth = created.contents
            auth['uri'] = created.uri

            # Find the DNS challenge
            try:
                auth['challenge'] = [ch for ch in auth.get('challenges', []) if ch.get('type') == 'dns-01'][0]
            except IndexError:
                raise ManualeError("Manuale only supports the dns-01 challenge. The server did not return one.")

            auth['key_authorization'] = "{}.{}".format(auth['challenge'].get('token'), thumbprint)
            digest = hashlib.sha256()
            digest.update(auth['key_authorization'].encode('ascii'))
            auth['txt_record'] = jose_b64(digest.digest())

            authz[domain] = auth

        logger.info("")
        logger.info("DNS verification required. Make sure these TXT records are in place:")
        logger.info("")
        for domain in domains:
            auth = authz[domain]
            logger.info("  _acme-challenge.{}.  IN TXT  \"{}\"".format(domain, auth['txt_record']))
        logger.info("")
        input("Press enter to continue.")

        # Verify each domain
        done, failed = set(), set()
        for domain in domains:
            logger.info("")
            auth = authz[domain]
            challenge = auth['challenge']
            acme.validate_authorization(challenge['uri'], 'dns-01', auth['key_authorization'])

            while True:
                logger.info("{}: waiting for verification. Checking in 5 seconds.".format(domain))
                time.sleep(5)

                response = acme.get_authorization(auth['uri'])
                status = response.get('status')
                if status == 'valid':
                    done.add(domain)
                    logger.info("{}: OK! Authorization lasts until {}.".format(domain, response.get('expires', '(not provided)')))
                    break
                elif status != 'pending':
                    failed.add(domain)

                    # Failed, dig up details
                    error_type, error_reason = "unknown", "N/A"
                    try:
                        challenge = [ch for ch in response.get('challenges', []) if ch.get('type') == 'dns-01'][0]
                        error_type = challenge.get('error').get('type')
                        error_reason = challenge.get('error').get('detail')
                    except (ValueError, IndexError, AttributeError, TypeError):
                        pass

                    logger.info("{}: {} ({})".format(domain, error_reason, error_type))
                    break

        logger.info("")
        if failed:
            logger.info("{} domain(s) authorized, {} failed.".format(len(done), len(failed)))
            logger.info("Authorized: {}".format(' '.join(done) or "N/A"))
            logger.info("Failed: {}".format(' '.join(failed)))
        else:
            logger.info("{} domain(s) authorized. Let's Encrypt!".format(len(done)))
    except IOError as e:
        logger.error("A connection or service error occurred. Aborting.")
        raise ManualeError(e)
