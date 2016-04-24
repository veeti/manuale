"""
A small container for account data. Ideally we would get away with just using a
PEM-encoded RSA private key as the account file, but we might need the account
URI at some point.
"""

import json

from .crypto import load_private_key, export_private_key


class Account:

    def __init__(self, key, uri=None):
        self.key = key
        self.uri = uri

    def serialize(self):
        return json.dumps({
            'key': export_private_key(self.key).decode('utf-8'),
            'uri': self.uri,
        }).encode('utf-8')


def deserialize(data):
    try:
        if not isinstance(data, str):
            data = data.decode('utf-8')
        data = json.loads(data)
        if 'key' not in data or 'uri' not in data:
            raise ValueError("Missing 'key' or 'uri' fields.")
        return Account(key=load_private_key(data['key'].encode('utf8')), uri=data['uri'])
    except (TypeError, ValueError, AttributeError) as e:
        raise IOError("Invalid account structure: {}".format(e))
