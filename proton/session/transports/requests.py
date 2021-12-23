from ..exceptions import *
from .base import Transport

import json

class RequestsTransport(Transport):
    """ This is a simple transport based on the requests library, it's not advised to use in production """
    def __init__(self, session):
        super().__init__(session)
        
        import requests
        self._s = requests.Session()

    @classmethod
    def _get_priority(cls):
        try:
            import requests
            return 3
        except ImportError:
            return None


    async def async_api_request(
        self, endpoint,
        jsondata=None, additional_headers=None,
        method=None, params=None
    ):
        import requests
        self._s.headers['x-pm-appversion'] = self._session.appversion
        self._s.headers['User-Agent'] = self._session.user_agent

        if self._session.authenticated:
            self._s.headers['x-pm-uid'] = self._session.UID
            self._s.headers['Authorization'] = 'Bearer ' + self._session.AccessToken

        # If we don't have an explicit method, default to get if there's no data, post otherwise
        if method is None:
            if jsondata is None:
                fct = self._s.get
            else:
                fct = self._s.post
        else:
            fct = {
                'get': self._s.get,
                'post': self._s.post,
                'put': self._s.put,
                'delete': self._s.delete,
                'patch': self._s.patch
            }.get(method.lower())

            if fct is None:
                raise ValueError("Unknown method: {}".format(method))

        try:
            ret = fct(
                self._environment.http_base_url + endpoint,
                headers=additional_headers,
                json=jsondata,
                params=params
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            raise ProtonAPINotReachable(e)
        except (Exception, requests.exceptions.BaseHTTPError) as e:
            raise ProtonAPIUnexpectedError(e)

        try:
            ret_json = ret.json()
        except json.decoder.JSONDecodeError:
            raise ProtonAPIError(ret.status_code, dict(ret.headers), {})

        if ret_json['Code'] not in [1000, 1001]:
            raise ProtonAPIError(ret.status_code, dict(ret.headers), ret_json)

        return ret_json
