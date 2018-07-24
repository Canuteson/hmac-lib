import hashlib
import hmac


class SignedMessage(object):
    def __init__(self, message_body, secret_key, message_signature=None):
        self.body = message_body
        self.secret_key = secret_key
        self.unverified_signature = message_signature

    @property
    def valid_signature(self):
        message = bytes(self.body).encode('utf-8')
        secret = bytes(self.secret_key).encode('utf-8')
        signature = hmac.new(secret, message, digestmod=hashlib.sha256).hexdigest()
        return signature

    @property
    def has_valid_signature(self):
        return self.valid_signature == self.unverified_signature
