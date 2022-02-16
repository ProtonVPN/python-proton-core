import weakref

class Transport:
    def __init__(self, session):
        self.__session = weakref.ref(session)
    
    @property
    def _session(self):
        return self.__session()

    @property
    def _environment(self):
        #Shortcut to access environment
        return self._session.environment

    def __eq__(self, other):
        # It's the same transport if it's the same type (that's what users would generally assume)
        return self.__class__ == other.__class__

    async def is_working(self):
        try:
            return await self.async_api_request('/tests/ping').get('Code') == '1000'
        except:
            return False

    async def async_api_request(
        self, endpoint,
        jsondata=None, additional_headers=None,
        method=None, params=None
    ):
        raise NotImplementedError("async_api_request should be implemented")

class TransportFactory:
    def __init__(self, cls, *args, **kwargs):
        self._cls = cls
        self._args = args
        self._kwargs = kwargs

    def __call__(self, session):
        return self._cls(session, *self._args, **self._kwargs)

    def __eq__(self, other):
        # It's the same transport if it's the same type (that's what users would generally assume)
        return self._cls == other._cls
