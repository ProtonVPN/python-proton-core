from asyncio import transports
from ..exceptions import *
from .base import Transport
from .aiohttp import AiohttpTransport
from .alternativerouting import AlternativeRoutingTransport

import json, base64, struct, time, asyncio, random, itertools

from urllib.parse import urlparse

from ..api import sync_wrapper

class AutoTransport(Transport):
    # We assume that a given transport fails after that number of seconds
    TIMEOUT_TRANSPORT = 15

    @classmethod
    def _get_priority(cls):
        return 100

    def __init__(self, session):
        super().__init__(session)

        self._current_transport = None
        self._transport_choices = [
            (0, AiohttpTransport),
            (5, AlternativeRoutingTransport)
        ]

    @property
    def transport_choices(self):
        return self._transport_choices

    @transport_choices.setter
    def transport_choices(self, newvalue):
        self._transport_choices = []

        for timeout, cls in newvalue:
            if not isinstance(cls, Transport):
                raise TypeError("Transports should be a subclass of Transport")
            self._transport_choices.append((timeout, cls))
        self._transport_choices.sort(key=lambda x: x[0])

    async def _ping_via_transport(self, timeout, transport):
        await asyncio.sleep(timeout)
        result = await asyncio.wait_for(transport.async_api_request('/tests/ping'), self.TIMEOUT_TRANSPORT)
        assert result == {"Code": 1000}, "For some reason, we didn't get {\"Code\":1000} ?!" # nosec (really just a sanity check, ping always return 1000 per spec)
        return transport

    async def find_available_transport(self):
        pending = []
        for timeout, cls in self._transport_choices:
            transport = cls(self._session)
            pending.append(asyncio.create_task(self._ping_via_transport(timeout, transport)))

        results_ok = []
        results_fail = []
        final_timestamp = time.time() + self.TIMEOUT_TRANSPORT
        while len(pending) > 0 and len(results_ok) == 0:
            done, pending = await asyncio.wait(pending, timeout=max(0.1, final_timestamp - time.time()), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    results_ok.append(task.result())
                except (ProtonAPINotAvailable, ProtonAPINotReachable) as e:
                    # That means that we were able to get to the API (wasn't reachable or was mitm'ed)
                    results_fail.append(e)
                except Exception as e:
                    # Unhandled exception, we might want to understand what is going on
                    for task in pending:
                        task.cancel()
                    raise
        
        for task in pending:
            task.cancel()
        
        if len(results_ok) > 0:
            self._current_transport = results_ok[0]

    async def async_api_request(
        self, endpoint,
        jsondata=None, data=None, additional_headers=None, method=None, params=None
    ):
        tries_left = 3
        while tries_left > 0:
            tries_left -= 1
            if self._current_transport is None:
                await self.find_available_transport()
            
            if self._current_transport is None:
                raise ProtonAPINotReachable("No working transports found")

            try:
                return await asyncio.wait_for(self._current_transport.async_api_request(endpoint, jsondata, data, additional_headers, method, params), self.TIMEOUT_TRANSPORT)
            except asyncio.TimeoutError:
                # Reset transport
                self._current_transport = None
            