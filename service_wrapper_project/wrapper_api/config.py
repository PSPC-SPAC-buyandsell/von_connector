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
from os import environ


_inis = [
    pjoin(dirname(abspath(__file__)), 'config', 'config.ini'),
    pjoin(dirname(abspath(__file__)), 'config', 'agent-profile', environ.get('AGENT_PROFILE') + '.ini')
]

def init_config():
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
