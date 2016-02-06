"""
The account info command.
"""

import json
import logging
import sys

from .acme import Acme
from .errors import ManualeError

logger = logging.getLogger(__name__)

def info(server, account):
    acme = Acme(server, account)

    try:
        logger.info("Requesting account data...")
        reg = acme.get_registration()
        sys.stdout.write(json.dumps(reg, indent=4, sort_keys=True))
        sys.stdout.flush()
    except IOError as e:
        raise ManualeError(e)
