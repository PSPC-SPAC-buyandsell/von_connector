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

from django.apps.config import AppConfig
from django.core.cache import cache
from os.path import abspath, dirname, join as pjoin
from os import environ
from rest_framework.exceptions import NotFound
from von_agent.agents import Issuer
from von_agent.demo_agents import TrustAnchorAgent, SRIAgent, BCRegistrarAgent, OrgBookAgent
from von_agent.nodepool import NodePool
from von_agent.wallet import Wallet
from wrapper_api.config import init_config
from wrapper_api.eventloop import do

import asyncio
import atexit
import json
import logging
import requests

def _cleanup():
    ag = cache.get('agent')
    if ag is not None:
        do(ag.close())

    p = cache.get('pool')
    if p is not None:
        do(p.close())

class WrapperApiConfig(AppConfig):
    name = 'wrapper_api'

    def originate(ag, cfg):
        """
        Send schemata that configuration identifies agent as originating, send claim definition if agent is an Issuer.

        :param ag: agent object
        :param cfg_agent: configuration dict
        """
        # note that for our demo, all issuers originate exactly the schemata on which they make claim definitions

        logger = logging.getLogger(__name__)

        if 'Origin' not in cfg:
            return
        for schema_name in cfg['Origin']:
            for schema_version in (v.strip() for v in cfg['Origin'][schema_name].split(',')):
                j = None
                attrs_json = None
                with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-lookup.json'), 'r') as proto_f:
                    j = proto_f.read()

                schema_json = do(ag.process_post(json.loads(j % (ag.did, schema_name, schema_version))))

                if not json.loads(schema_json):
                    with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-send.json'), 'r') as proto_f:
                        j = proto_f.read()
                    with open(pjoin(
                            dirname(abspath(__file__)),
                            'protocol',
                            'schema-send',
                            schema_name,
                            schema_version,
                            'attr-names.json'), 'r') as attr_names_f:
                        attrs_json = attr_names_f.read()
                    schema_json = do(ag.process_post(json.loads(j % (
                        ag.did,
                        schema_name,
                        schema_version,
                        json.dumps(json.loads(attrs_json))))))
                    logger.info('Originated schema {} version {}'.format(schema_name, schema_version))

                schema = json.loads(schema_json)
                assert schema

                if isinstance(ag, Issuer):
                    claim_def_json = do(ag.get_claim_def(schema['seqNo'], ag.did))
                    if json.loads(claim_def_json):
                        logger.info('Using existing claim def on ledger for schema {} version {}'.format(
                            schema_name,
                            schema_version))
                    else:
                        do(ag.send_claim_def(schema_json))
                        logger.info('Created claim def on ledger for schema {} version {}'.format(
                            schema_name,
                            schema_version))

    def agent_config_for(cfg):
        return {
            'endpoint': 'http://{}:{}/{}'.format(
                cfg['Agent']['host'],
                int(cfg['Agent']['port']),
                cfg['VON Connector']['api.base.url.path'].strip('/')),
            'proxy-relay': True
        }

    def ready(self):
        logger = logging.getLogger(__name__)

        cfg = init_config()
        base_api_url_path = cfg['VON Connector']['api.base.url.path'].strip('/')

        role = (cfg['Agent']['role'] or '').lower().replace(' ', '')  # will be a dir as a pool name: spaces are evil
        profile = environ.get('AGENT_PROFILE').lower().replace(' ', '') # several profiles may share a role
        logging.debug('Starting agent; profile={}, role={}'.format(profile, role))

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
                Wallet(p.name, cfg['Agent']['seed'], profile, None),
                WrapperApiConfig.agent_config_for(cfg))
            do(ag.open())
            assert ag.did
            tag_did = ag.did
            
            # register trust anchor if need be
            if not json.loads(do(ag.get_nym(ag.did))):
                do(ag.send_nym(ag.did, ag.verkey, ag.wallet.profile))
            if not json.loads(do(ag.get_endpoint(ag.did))):
                do(ag.send_endpoint())

            # originate schemata if need be
            WrapperApiConfig.originate(ag, cfg)

        elif role in ('sri', 'org-book', 'bc-registrar'):
            # create agent via factory by role
            if role == 'sri':
                ag = SRIAgent(
                    p,
                    Wallet(p.name, cfg['Agent']['seed'], profile, None),
                    WrapperApiConfig.agent_config_for(cfg))
            elif role == 'org-book':
                ag = OrgBookAgent(
                    p,
                    Wallet(p.name, cfg['Agent']['seed'], profile, None),
                    WrapperApiConfig.agent_config_for(cfg))
            elif role == 'bc-registrar':
                ag = BCRegistrarAgent(
                    p,
                    Wallet(p.name, cfg['Agent']['seed'], profile, None),
                    WrapperApiConfig.agent_config_for(cfg))

            do(ag.open())
            logging.debug('profile {}; ag class {}'.format(profile, ag.__class__.__name__))

            trust_anchor_base_url = 'http://{}:{}/{}'.format(
                cfg['Trust Anchor']['host'],
                cfg['Trust Anchor']['port'],
                cfg['VON Connector']['api.base.url.path'].strip('/'))

            # get nym: if not registered; get trust-anchor host & port, post an agent-nym-send form
            if not json.loads(do(ag.get_nym(ag.did))):
                # trust anchor DID is necessary
                try:
                    r = requests.get('{}/did'.format(trust_anchor_base_url))
                    if not r.ok:
                        logging.error(
                            'Agent {} nym is not on the ledger, but trust anchor is not responding'.format(profile))
                        r.raise_for_status()
                    tag_did = r.json()
                    logging.debug('{}; tag_did {}'.format(profile, tag_did))
                    assert tag_did

                    with open(pjoin(dirname(abspath(__file__)), 'protocol', 'agent-nym-send.json'), 'r') as proto:
                        j = proto.read()
                    logging.debug('{}; sending {}'.format(profile, j % (ag.did, ag.verkey)))
                    r = requests.post(
                        '{}/agent-nym-send'.format(trust_anchor_base_url),
                        json=json.loads(j % (ag.did, ag.verkey)))
                    r.raise_for_status()
                except Exception:
                    raise NotFound(
                        detail='Agent {} requires Trust Anchor agent, but it is not responding'.format(profile),
                        code=500)

            # get endpoint: if not present, send it
            if not json.loads(do(ag.get_endpoint(ag.did))):
                do(ag.send_endpoint())

            if role in ('bc-registrar', 'sri'):
                # originate schemata if need be
                WrapperApiConfig.originate(ag, cfg)

            if role in ('org-book'):
                # set master secret
                from os import getpid
                # append pid to avoid re-using a master secret on restart of HolderProver agent; indy-sdk library 
                # is shared, so it remembers and forbids it unless we shut down all processes
                do(ag.create_master_secret(cfg['Agent']['master.secret'] + '.' + str(getpid())))

        else:
            raise ValueError('Agent profile {} configured for unsupported role {}'.format(profile, role))

        assert ag is not None

        cache.set('agent', ag)
        atexit.register(_cleanup)
