"""
Copyright (c) 2023 Proton AG

This file is part of Proton.

Proton is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from asyncio import transports, TimeoutError
from typing import List
from unittest.mock import Mock
from urllib.parse import urlparse
import json, base64, struct, time, asyncio, random, itertools

from ..exceptions import *
from .base import Transport
from .aiohttp import AiohttpTransport
from .alternativerouting import AlternativeRoutingTransport
from ..api import sync_wrapper


class AutoTransport(Transport):
    # We assume that a given transport fails after that number of seconds
    TRANSPORT_TIMEOUT = 15

    @classmethod
    def _get_priority(cls):
        return 100

    def __init__(self, session, transport_choices: List[Transport] = None, transport_timeout: int = None):
        super().__init__(session)

        self._current_transport = None
        self._transport_choices = transport_choices or [
            (0, AiohttpTransport),
            (5, AlternativeRoutingTransport)
        ]
        self._transport_timeout = transport_timeout or self.TRANSPORT_TIMEOUT

    @property
    def is_available(self) -> bool:
        return self._current_transport is not None

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
        ping_url = "/tests/ping"
        try:
            result = await asyncio.wait_for(transport.async_api_request(ping_url), self._transport_timeout)
        except TimeoutError as error:
            raise ProtonAPINotReachable(
                f"{type(transport).__name__} transport not available: unable to reach {ping_url}"
            ) from error
        if result != {"Code": 1000}:
            raise ProtonAPINotAvailable(
                f"{type(transport).__name__} transport received unexpected response from {ping_url}:\n"
                f"{result}"
            )
        return transport

    async def find_available_transport(self):
        pending = []
        for timeout, cls in self._transport_choices:
            transport = cls(self._session)
            pending.append(asyncio.create_task(self._ping_via_transport(timeout, transport)))

        results_ok = []
        results_fail = []
        final_timestamp = time.time() + self._transport_timeout
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

        if not results_ok:
            raise ProtonAPINotReachable("No working transports found")

        self._current_transport = results_ok[0]

    async def async_api_request(
        self, endpoint,
        jsondata=None, data=None, additional_headers=None, method=None, params=None,
        return_raw=False
    ):
        tries_left = 3
        while tries_left > 0:
            tries_left -= 1
            if self._current_transport is None:
                await self.find_available_transport()

            try:
                return await asyncio.wait_for(self._current_transport.async_api_request(endpoint, jsondata, data, additional_headers, method, params, return_raw=return_raw), self._transport_timeout)
            except asyncio.TimeoutError:
                # Reset transport
                self._current_transport = None

        raise ProtonAPINotReachable("Timeout accessing the API")  # we should not reach that point except in case of Timeout
