"""
Copyright 2017 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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

from configparser import ConfigParser
from django.conf import settings
from django.core.cache import cache
from os.path import abspath, dirname, isfile, join as pjoin
from os import environ, makedirs

import logging


_inis = [
    pjoin(dirname(abspath(__file__)), 'config', 'config.ini'),
    pjoin(dirname(abspath(__file__)), 'config', 'agent-profile', environ.get('AGENT_PROFILE') + '.ini')
]


def init_logging():
    dir_log = pjoin(dirname(abspath(__file__)), 'log')
    makedirs(dir_log, exist_ok=True)
    path_log = pjoin(dir_log, environ.get('AGENT_PROFILE') + '.log')

    LOG_FORMAT='%(asctime)-15s | %(levelname)-8s | %(name)-12s | %(message)s'
    logging.basicConfig(filename=path_log, level=logging.INFO, format=LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
    logging.getLogger('asyncio').setLevel(logging.ERROR)
    logging.getLogger('von_agent').setLevel(logging.DEBUG)
    logging.getLogger('indy').setLevel(logging.ERROR)
    logging.getLogger('requests').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)


def init_config():
    init_logging()

    global _inis
    if cache.get('config') == None:
        if all(isfile(ini) for ini in _inis):
            parser = ConfigParser()
            for ini in _inis: 
                parser.read(ini)
            cache.set(
                'config',
                {s: dict(parser[s].items()) for s in parser.sections()})
        else:
            raise FileNotFoundError('Configuration file(s) missing; check {}'.format(_inis))
    return cache.get('config')
