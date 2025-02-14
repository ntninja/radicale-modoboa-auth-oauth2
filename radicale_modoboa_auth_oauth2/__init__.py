"""Authentication plugin for Radicale."""

import requests

from radicale import auth
from radicale.log import logger


class Auth(auth.BaseAuth):

    def __init__(self, configuration):
        super().__init__(configuration)
        try:
            self._endpoint = configuration.get("auth", "oauth2_introspection_endpoint")
        except KeyError:
            raise RuntimeError("oauth2_introspection_endpoint must be set")
        logger.warning("Using oauth2 introspection endpoint: %s" % (self._endpoint))

    def _login(self, login, password):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "token": password
        }
        response = requests.post(self._endpoint, data=data, headers=headers)
        content = response.json()
        if response.status_code == 200 and content.get("active") and content.get("username") == login:
            return login
        return ""
