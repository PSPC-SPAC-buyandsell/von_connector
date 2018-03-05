"""
Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import asyncio
import logging

from os import environ

import pytest

from indy import wallet, pool, did, ledger


logging.basicConfig(level=logging.DEBUG)
logging.getLogger("wrapper_api").setLevel(logging.WARN)
logging.getLogger("von_agent").setLevel(logging.INFO)
logging.getLogger("indy").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def pool_ip():
    logger = logging.getLogger(__name__)
    logger.debug("pool_ip: >>>")

    res = environ.get("TEST_POOL_IP", "127.0.0.1")

    logger.debug("pool_ip: <<< res: %r", res)
    return res
