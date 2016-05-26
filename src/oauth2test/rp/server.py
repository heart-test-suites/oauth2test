import logging

from future.backports.urllib.parse import urlparse
from oic import oauth2
from oic.exception import ParseError
from oic.extension.message import RegistrationRequest

logger = logging.getLogger(__name__)


class Server(oauth2.Server):

    def _parse_request(self, request, data, sformat, client_id=None):
        if sformat == "json":
            request = request().from_json(data)
        elif sformat == "jwt":
            request = request().from_jwt(data, keyjar=self.keyjar)
        elif sformat == "urlencoded":
            if '?' in data:
                parts = urlparse(data)
                scheme, netloc, path, params, query, fragment = parts[:6]
            else:
                query = data
            request = request().from_urlencoded(query)
        else:
            raise ParseError("Unknown package format: '%s'" % sformat,
                             request)

        # get the verification keys
        if client_id:
            keys = self.keyjar.verify_keys(client_id)
            sender = client_id
        else:
            try:
                keys = self.keyjar.verify_keys(request["client_id"])
                sender = request['client_id']
            except KeyError:
                keys = None
                sender = ''

        logger.debug("verify keys: {}".format(keys))
        request.verify(key=keys, keyjar=self.keyjar, sender=sender)
        return request

    def parse_registration_request(self, data, sformat="urlencoded"):
        return self._parse_request(RegistrationRequest, data, sformat)

