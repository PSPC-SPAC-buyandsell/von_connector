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

from django.apps.config import AppConfig
from django.core.cache import cache
from os.path import abspath, dirname, join as pjoin
from os import environ
from von_agent.nodepool import NodePool
from von_agent.demo_agents import TrustAnchorAgent, SRIAgent, BCRegistrarAgent, OrgBookAgent
from wrapper_api.config import init_config
from wrapper_api.eventloop import do

import asyncio
import atexit
import json
import logging
import requests


PATH_PREFIX_SLASH='api/v0/'

LOG_FORMAT='%(levelname)-8s | %(name)-12s | %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logging.getLogger('asyncio').setLevel(logging.ERROR)
logging.getLogger('von_agent').setLevel(logging.ERROR)
logging.getLogger('indy').setLevel(logging.ERROR)
logging.getLogger('requests').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)


def _cleanup():
    ag = cache.get('agent')
    if ag is not None:
        do(ag.close())

    p = cache.get('pool')
    if p is not None:
        do(p.close())

class WrapperApiConfig(AppConfig):
    name = 'wrapper_api'

    def ready(self):
        logger = logging.getLogger(__name__)

        cfg = init_config()
        base_api_url_path = PATH_PREFIX_SLASH.strip('/')

        role = (cfg['Agent']['role'] or '').lower().replace(' ', '')  # will be a dir as a pool name: spaces are evil
        profile = environ.get('AGENT_PROFILE').lower().replace(' ', '') # several profiles may share a role
        logging.debug("Starting agent; profile={}, role={}".format(profile, role))

        p = None  # the node pool
        p = NodePool('pool.{}'.format(profile), cfg['Pool']['genesis.txn.path'])
        do(p.open())
        assert p.handle
        cache.set('pool', p)

        ag = None
        if role == 'trust-anchor':
            bootstrap_json = cfg['Agent']
            ag = TrustAnchorAgent(
                p,
                cfg['Agent']['seed'],
                'wallet-{}'.format(profile),
                None,
                cfg['Agent']['host'],
                int(cfg['Agent']['port']),
                base_api_url_path)
            do(ag.open())
            assert ag.did
            tag_did = ag.did
            
            # register trust anchor if need be
            if not json.loads(do(ag.get_nym(ag.did))):
                do(ag.send_nym(ag.did, ag.verkey))
            if not json.loads(do(ag.get_endpoint(ag.did))):
                do(ag.send_endpoint())

            # send schema if need be, seeding schema cache en passant
            with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-lookup.json'), 'r') as proto:
                j = proto.read()
            if not json.loads(do(ag.process_post(json.loads(j % (
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version']))))):
                with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-send.json'), 'r') as proto:
                    j = proto.read()
                schema = do(ag.process_post(json.loads(j % (
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version']))))
                assert schema

        elif role in ('sri', 'org-book', 'bc-registrar'):
            # create agent via factory by role
            if role == 'sri':
                ag = SRIAgent(
                    p,
                    cfg['Agent']['seed'],
                    'wallet-{}'.format(profile),
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    base_api_url_path)
            elif role == 'org-book':
                ag = OrgBookAgent(
                    p,
                    cfg['Agent']['seed'],
                    'wallet-{}'.format(profile),
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    PATH_PREFIX_SLASH.strip('/'))
            elif role == 'bc-registrar':
                ag = BCRegistrarAgent(
                    p,
                    cfg['Agent']['seed'],
                    'wallet-{}'.format(profile),
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    base_api_url_path)

            do(ag.open())
            logging.debug("profile {}; ag class {}".format(profile, ag.__class__.__name__))

            trust_anchor_host = cfg['Trust Anchor']['host']
            trust_anchor_port = cfg['Trust Anchor']['port']

            # trust anchor DID is necessary
            r = requests.get('http://{}:{}/{}/did'.format(trust_anchor_host, trust_anchor_port, base_api_url_path))
            r.raise_for_status()
            tag_did = r.json()
            assert tag_did

            logging.debug("{}; tag_did {}".format(profile, tag_did))
            # get nym: if not registered; get trust-anchor host & port, post an agent-nym-send form
            if not json.loads(do(ag.get_nym(ag.did))):
                with open(pjoin(dirname(abspath(__file__)), 'protocol', 'agent-nym-send.json'), 'r') as proto:
                    j = proto.read()
                logging.debug("{}; sending {}".format(profile, j % (ag.did, ag.verkey)))
                r = requests.post(
                    'http://{}:{}/{}/agent-nym-send'.format(trust_anchor_host, trust_anchor_port, base_api_url_path),
                    json=json.loads(j % (ag.did, ag.verkey)))
                r.raise_for_status()

            # get endpoint: if not present, send it
            if not json.loads(do(ag.get_endpoint(ag.did))):
                do(ag.send_endpoint())

            # Post a schema_lookup, seeding schema cache and obviating need to specify schema in POST messages
            with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-lookup.json'), 'r') as proto:
                j = proto.read()
            schema_json = do(ag.process_post(json.loads(j % (
                tag_did,
                cfg['Schema']['name'],
                cfg['Schema']['version']))))
            assert json.loads(schema_json)

            if role in ('bc-registrar', 'sri'):
                # issuer send claim def
                do(ag.send_claim_def(schema_json))

            if role in ('org-book'):
                # set master secret
                from os import getpid
                # append pid to avoid re-using a master secret on restart of HolderProver agent; indy-sdk library 
                # is shared, so it remembers and forbids it unless we shut down all processes
                do(ag.create_master_secret(cfg['Agent']['master.secret'] + '.' + str(getpid())))

        else:
            raise ValueError('Unsupported agent role [{}]'.format(role))

        assert ag is not None
        assert ag._schema_cache

        cache.set('agent', ag)
        atexit.register(_cleanup)
