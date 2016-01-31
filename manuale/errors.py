class ManualeError(Exception):
    pass


class AcmeError(IOError):
    def __init__(self, response):
        message = "The ACME request failed."
        try:
            details = response.json()
            self.type = details.get('type', 'unknown')
            message = "{} (type {}, HTTP {})".format(details.get('detail'),
                    self.type, response.status_code)
        except (ValueError, TypeError, AttributeError):
            pass
        super().__init__(message)


class AccountAlreadyExistsError(AcmeError):

    def __init__(self, response, existing_uri):
        super().__init__(response)
        self.existing_uri = existing_uri
