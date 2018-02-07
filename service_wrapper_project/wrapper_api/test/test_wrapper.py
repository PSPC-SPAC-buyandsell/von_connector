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

from collections import Counter
from configparser import ConfigParser
from contextlib import closing
from os import walk
from os.path import abspath, dirname, isfile, join as pjoin
from time import sleep
from von_agent.util import ppjson, claims_for, encode, prune_claims_json, revealed_attrs, schema_keys_for
from von_agent.proto.proto_util import list_schemata, attr_match, req_attrs, pred_match, pred_match_match
from von_agent.schema import SchemaKey, SchemaStore

import atexit
import datetime
import json
import pexpect
import pytest
import requests
import socket


def shutdown(wrappers):
    for wrapper in wrappers.values():
        wrapper.stop()


def is_up(host, port):
    rc = 0
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(5)
        rc = sock.connect_ex((host, port))
    return (rc == 0)


class Wrapper:
    def __init__(self, agent_profile, agent_cfg):
        self._script = pjoin(dirname(dirname(dirname(abspath(__file__)))), 'bin', agent_profile)
        self._agent_profile = agent_profile
        self._host = agent_cfg['host']
        self._port = int(agent_cfg['port'])
        self._proc = None

    def is_up(self):
        return is_up(self._host, self._port)

    def start(self):
        if self.is_up():
            return False

        self._proc = pexpect.spawn(self._script)
        rc = self._proc.expect(
            [
                'Quit the server with CONTROL-C[.]',
                'indy[.]error[.]IndyError.+\r\n',
                pexpect.EOF,
                pexpect.TIMEOUT
            ],
            timeout=240)
        if rc == 1:
            raise ValueError('Service wrapper for {} error: {}'.format(
                self._agent_profile,
                self._proc.after.decode()))
        elif rc == 2:
            raise ValueError('Service wrapper for {} stopped: {}'.format(
                self._agent_profile,
                self._proc.before.decode()))
        elif rc == 3:
            raise ValueError('Timed out waiting on service wrapper for {}'.format(
                self._agent_profile))
        return True

    def stop(self):
        if self._proc and self._proc.isalive():
            self._proc.sendcontrol('c')
            print("\n\n== X == sleeping a few seconds to allow {} to clean up".format(self._agent_profile))
            sleep(3)  # give it enough time to clean up ~/.indy_client/...
            if self._proc.isalive():
                self._proc.close()


def set_docker():
    script = pjoin(dirname(dirname(dirname(abspath(__file__)))), 'bin', 'set-docker')
    proc = pexpect.spawn(script)
    rc = proc.expect(['^0\r\n', '^1\r\n', pexpect.EOF, pexpect.TIMEOUT], timeout=15)
    if rc == 1:
        raise ValueError('Docker container/network could not start')
    elif rc == 2:
        raise ValueError('Docker script stopped: {}'.format(proc.before.decode()))
    elif rc == 3:
        raise ValueError('Timed out waiting on docker script')
    return rc


def form_json(msg_type, args, proxy_did=None):
    assert all(isinstance(x, str) for x in args)
    # print("... form_json interpolands {}".format([a for a in args]))

    with open(pjoin(dirname(dirname(abspath(__file__))), 'protocol', '{}.json'.format(msg_type)), 'r') as proto:
        raw_json = proto.read()
    # print("... raw_json: {}".format(raw_json))
    msg_json = raw_json % args
    rv = msg_json
    if proxy_did:
        assert msg_type in (
            'agent-nym-send',
            'agent-endpoint-send',
            'claim-def-send',
            'claim-hello',
            'claim-store',
            'claim-request',
            'proof-request',
            'proof-request-by-referent',
            'verification-request')
        # print("... form_json json-loading {}".format(msg_json))
        msg = json.loads(msg_json)
        msg['data']['proxy-did'] = proxy_did
        rv = json.dumps(msg, indent=4)
    # print('... form_json composed {} form: {}'.format(msg_type, ppjson(rv)))
    return rv


def url_for(cfg_section, suffix=''):
    rv = 'http://{}:{}/api/v0/{}'.format(cfg_section['host'], cfg_section['port'], suffix).strip('/')
    # print('... interpolated URL: {}'.format(rv))
    return rv


def get_post_response(cfg_section, msg_type, args, proxy_did=None, rc_http=200):
    assert all(isinstance(x, str) for x in args)
    url = url_for(cfg_section, msg_type)
    r = requests.post(url, json=json.loads(form_json(msg_type, args, proxy_did=proxy_did)))
    assert r.status_code == rc_http
    return r.json()


def claim_value_pair(plain):
    return [str(plain), encode(plain)]


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_wrapper(pool_ip):
    agent_profiles = ['trust-anchor', 'sri', 'pspc-org-book', 'bc-org-book', 'bc-registrar']

    # 0. configure
    cfg = {}
    parser = ConfigParser()
    ini = pjoin(dirname(dirname(abspath(__file__))), 'config', 'config.ini')
    assert isfile(ini)
    parser.read(ini)
    cfg = {s: dict(parser[s].items()) for s in parser.sections()}

    for agent_profile in agent_profiles:
        ini = pjoin(dirname(dirname(abspath(__file__))), 'config', 'agent-profile', '{}.ini'.format(agent_profile))
        assert isfile(ini)
        agent_parser = ConfigParser()
        agent_parser.read(ini)

        cfg[agent_profile] = {s: dict(agent_parser[s].items()) for s in agent_parser.sections()}

    print('\n\n== 0 == Test config: {}'.format(ppjson(cfg)))

    # 1. check docker & start wrappers
    if is_up(pool_ip, 9702):
        print('\n\n== 1 == Using running indy pool network at {}'.format(pool_ip))
    else:
        set_docker()
        print('\n\n== 1 == Started indy pool network via docker at {}'.format(pool_ip))
    service_wrapper = {}
    for agent_profile in agent_profiles:
        service_wrapper[agent_profile] = Wrapper(agent_profile, cfg[agent_profile]['Agent'])
        started = service_wrapper[agent_profile].start()
        print('\n\n== 2.{} == {} wrapper: {} on {}:{}'.format(
            agent_profiles.index(agent_profile),
            'started' if started else 'using running',
            agent_profile,
            cfg[agent_profile]['Agent']['host'],
            cfg[agent_profile]['Agent']['port']))
    atexit.register(shutdown, service_wrapper)

    # 2. ensure all demo agents (wrappers) are up
    agent_profile2did = {}
    for agent_profile in agent_profiles:
        url = url_for(cfg[agent_profile]['Agent'], 'did')
        # print('\n... url {}'.format(url))
        r = requests.get(url)
        # print('\n... done req\n')
        assert r.status_code == 200
        agent_profile2did[agent_profile] = r.json()
    # trust-anchor: V4SGRU86Z58d6TV7PBUe6f
    # sri: FaBAq1W5QTVDpAZtep6h19
    # bc-org-book: Rzra4McufsSNUQ1mGyWc2w
    # pspc-org-book: 45UePtKtVrZ6UycN9gmMsG
    # bc-registrar: Q4zqM7aXqm7gDQkUVLng9h
    print('\n\n== 3 == DIDs: {}'.format(ppjson(agent_profile2did)))

    S_KEY = {
        'BC': SchemaKey(agent_profile2did['bc-registrar'], 'bc-reg', '1.0'),
        'SRI-1.0': SchemaKey(agent_profile2did['sri'], 'sri', '1.0'),
        'SRI-1.1': SchemaKey(agent_profile2did['sri'], 'sri', '1.1'),
        'GREEN': SchemaKey(agent_profile2did['sri'], 'green', '1.0'),
    }
    schema_key2issuer_agent_profile = {
        S_KEY['BC']: 'bc-registrar',
        S_KEY['SRI-1.0']: 'sri',
        S_KEY['SRI-1.1']: 'sri',
        S_KEY['GREEN']: 'sri'
    }
    claim = {}

    # 3. get schemata
    schema_store = SchemaStore()

    i = 0
    for profile in agent_profiles:
        if 'Origin' not in cfg[profile]:
            continue
        for name in cfg[profile]['Origin']:  # read each schema once - each schema has one originator
            for version in (v.strip() for v in cfg[profile]['Origin'][name].split(',')):
                s_key = SchemaKey(agent_profile2did[profile], name, version)
                schema_store[s_key] = get_post_response(
                    cfg[profile]['Agent'],
                    'schema-lookup', 
                    (
                        agent_profile2did[profile],
                        name,
                        version
                    ))
                print('\n\n== 4.{} == Schema [{}]: {}'.format(i, s_key, ppjson(schema_store[s_key])))
                i += 1

    # 4. BC Org Book, PSPC Org Book (as HolderProvers) respond to claims-reset directive, to restore state to base line
    for profile in ('bc-org-book', 'pspc-org-book'):
        reset_resp = get_post_response(
            cfg[profile]['Agent'],
            'claims-reset',
            ())
        assert not reset_resp

    # 5. Issuers send claim-hello to HolderProvers
    claim_req = {}
    i = 0
    for s_key in schema_store.index().values():
        claim_req[s_key] = get_post_response(
            cfg['bc-registrar']['Agent']
                if s_key.origin_did == agent_profile2did['bc-registrar']
                else cfg['sri']['Agent'],
            'claim-hello',
            (*s_key, s_key.origin_did),
            agent_profile2did['bc-org-book']
                if s_key.origin_did == agent_profile2did['bc-registrar']
                else agent_profile2did['pspc-org-book'])
        assert claim_req[s_key]
        print('\n\n== 5.{} == Claim request {}: {}'.format(i, s_key, ppjson(claim_req[s_key])))
        i += 1

    # 6. BC Registrar creates claims and stores at BC Org Book (as HolderProver)
    claim_data = {
        S_KEY['BC']: [
            {
                'id': 1,
                'busId': '11121398',
                'orgTypeId': 2,
                'jurisdictionId': 1,
                'legalName': 'The Original House of Pies',
                'effectiveDate': '2010-10-10',
                'endDate': None
            },
            {
                'id': 2,
                'busId': '11133333',
                'orgTypeId': 1,
                'jurisdictionId': 1,
                'legalName': 'Planet Cake',
                'effectiveDate': '2011-10-01',
                'endDate': None
            },
            {
                'id': 3,
                'busId': '11144444',
                'orgTypeId': 2,
                'jurisdictionId': 1,
                'legalName': 'Tart City',
                'effectiveDate': '2012-12-01',
                'endDate': None
            }
        ],
        S_KEY['SRI-1.0']: [],
        S_KEY['SRI-1.1']: [],
        S_KEY['GREEN']: []
    }
    i = 0
    for s_key in claim_data:
        for c in claim_data[s_key]:
            claim[s_key] = get_post_response(
                cfg[schema_key2issuer_agent_profile[s_key]]['Agent'],
                'claim-create',
                (json.dumps(claim_req[s_key]), json.dumps(c)))
            assert claim[s_key]
            print('\n\n== 6.{} == BC claim: {}'.format(i, ppjson(claim[s_key])))
            i += 1
            get_post_response(
                cfg[schema_key2issuer_agent_profile[s_key]]['Agent'],
                'claim-store',
                (   
                    json.dumps(claim[s_key]),
                ),
                agent_profile2did['bc-org-book'])

    # 7. SRI agent proxies to BC Org Book (as HolderProver) to find claims; actuator filters post hoc
    bc_claims_all = get_post_response(
        cfg['sri']['Agent'],
        'claim-request',
        (json.dumps(list_schemata([S_KEY['BC']])), json.dumps([]), json.dumps([]), json.dumps([])),
        agent_profile2did['bc-org-book'])
    print('\n\n== 7 == All BC claims, no filter: {}'.format(ppjson(bc_claims_all)))
    assert bc_claims_all

    bc_display_pruned_filt_post_hoc = claims_for(
        bc_claims_all['claims'],
        {
            S_KEY['BC']: {
                'legalName': claim_data[S_KEY['BC']][2]['legalName']
            }
        })
    print('\n\n== 8 == BC display claims filtered post-hoc matching {}: {}'.format(
        claim_data[S_KEY['BC']][2]['legalName'],
        ppjson(bc_display_pruned_filt_post_hoc)))

    get_post_response(  # exercise proof restriction to one claim per attribute
        cfg['sri']['Agent'],
        'proof-request',
        (json.dumps(list_schemata([S_KEY['BC']])), json.dumps([]), json.dumps([]), json.dumps([])),
        agent_profile2did['bc-org-book'],
        500)

    bc_display_pruned = prune_claims_json(bc_claims_all['claims'], {k for k in bc_display_pruned_filt_post_hoc})
    print('\n\n== 9 == BC claims stripped down {}'.format(ppjson(bc_display_pruned)))

    bc_claims_prefilt = get_post_response(
        cfg['sri']['Agent'],
        'claim-request',
        (
            json.dumps(list_schemata([S_KEY['BC']])),
            json.dumps([
                attr_match(
                    S_KEY['BC'],
                    {k: claim_data[S_KEY['BC']][2][k] for k in claim_data[S_KEY['BC']][2]
                        if k in ('jurisdictionId', 'busId')})
            ]),
            json.dumps([]),
            json.dumps([])
        ),
        agent_profile2did['bc-org-book'])
    assert bc_claims_prefilt

    print('\n\n== 10 == BC claims filtered a priori {}'.format(ppjson(bc_claims_prefilt)))
    bc_display_pruned_prefilt = claims_for(bc_claims_prefilt['claims'])
    print('\n\n== 11 == BC display claims filtered a priori matching {}: {}'.format(
        claim_data[S_KEY['BC']][2]['legalName'],
        ppjson(bc_display_pruned_prefilt)))
    assert set([*bc_display_pruned_filt_post_hoc]) == set([*bc_display_pruned_prefilt])
    assert len(bc_display_pruned_filt_post_hoc) == 1

    # 8. BC Org Book (as HolderProver) creates proof and responds to request for proof (by filter)
    bc_proof_resp = get_post_response(
        cfg['sri']['Agent'],
        'proof-request',
        (
            json.dumps(list_schemata([S_KEY['BC']])),
            json.dumps([
                attr_match(
                    S_KEY['BC'],
                    {k: claim_data[S_KEY['BC']][2][k] for k in claim_data[S_KEY['BC']][2]
                        if k in ('jurisdictionId', 'busId')})
            ]),
            json.dumps([]),
            json.dumps([])
        ),
        agent_profile2did['bc-org-book'])
    print('\n\n== 12 == BC proof (req by filter): {}'.format(ppjson(bc_proof_resp)))
    assert bc_proof_resp

    # 9. SRI Agent (as Verifier) verifies proof (by filter)
    bc_verification_resp = get_post_response(
        cfg['sri']['Agent'],
        'verification-request',
        (
            json.dumps(bc_proof_resp['proof-req']),
            json.dumps(bc_proof_resp['proof'])
        ))

    print('\n\n== 13 == SRI agent verifies BC proof (by filter) as {}'.format(ppjson(bc_verification_resp)))
    assert bc_verification_resp

    # 10. BC Org Book agent (as HolderProver) creates proof (by referent)
    bc_referent = set([*bc_display_pruned_prefilt]).pop()
    s_key = set(schema_keys_for(bc_claims_prefilt['claims'], {bc_referent}).values()).pop()  # it's unique
    bc_proof_resp = get_post_response(
        cfg['sri']['Agent'],
        'proof-request-by-referent',
        (
            json.dumps(list_schemata([s_key])),
            json.dumps([bc_referent]),
            json.dumps([])
        ),
        agent_profile2did['bc-org-book'])
    assert bc_proof_resp

    # 11. BC Org Book agent (as HolderProver) creates non-proof by non-referent
    get_post_response(
        cfg['sri']['Agent'],
        'proof-request-by-referent',
        (
            json.dumps(list_schemata([S_KEY['BC']])),
            json.dumps(['claim::ffffffff-ffff-ffff-ffff-ffffffffffff']),
            json.dumps([])
        ),
        agent_profile2did['bc-org-book'],
        500)

    # 12. SRI Agent (as Verifier) verifies proof (by referent)
    sri_bc_verification_resp = get_post_response(
        cfg['sri']['Agent'],
        'verification-request',
        (
            json.dumps(bc_proof_resp['proof-req']),
            json.dumps(bc_proof_resp['proof'])
        ))
    print('\n\n== 14 == SRI agent verifies BC proof (by referent={}) as {}'.format(
        bc_referent,
        ppjson(sri_bc_verification_resp)))
    assert sri_bc_verification_resp

    # 13. BC Org Book agent (as HolderProver) finds claims by predicate on default attr-match, req-attrs w/schema
    claims_found_pred = get_post_response(
        cfg['sri']['Agent'],
        'claim-request',
        (
            json.dumps(list_schemata([S_KEY['BC']])),
            json.dumps([]),
            json.dumps([
                pred_match(
                    S_KEY['BC'],
                    [
                        pred_match_match('id', '>=', claim_data[S_KEY['BC']][2]['id'])
                    ]
                )
            ]),
            json.dumps([req_attrs(S_KEY['BC'])])
        ),
        agent_profile2did['bc-org-book'])
    assert (set(req_attr['name'] for req_attr in claims_found_pred['proof-req']['requested_attrs'].values()) ==
        set(schema_store[S_KEY['BC']]['data']['attr_names']) - {'id'})
    assert (set(req_pred['attr_name']
        for req_pred in claims_found_pred['proof-req']['requested_predicates'].values()) == {'id'})

    # 14. BC Org Book agent (as HolderProver) finds claims by predicate on default attr-match and req-attrs
    claims_found_pred = get_post_response(
        cfg['sri']['Agent'],
        'claim-request',
        (
            json.dumps(list_schemata([S_KEY['BC']])),
            json.dumps([]),
            json.dumps([
                pred_match(
                    S_KEY['BC'],
                    [
                        pred_match_match('id', '>=', claim_data[S_KEY['BC']][2]['id'])
                    ]
                )
            ]),
            json.dumps([])
        ),
        agent_profile2did['bc-org-book'])
    assert (set(req_attr['name'] for req_attr in claims_found_pred['proof-req']['requested_attrs'].values()) ==
        set(schema_store[S_KEY['BC']]['data']['attr_names']) - {'id'})
    assert (set(req_pred['attr_name']
        for req_pred in claims_found_pred['proof-req']['requested_predicates'].values()) == {'id'})

    print('\n\n== 15 == BC claims structure by predicate: {}'.format(ppjson(claims_found_pred)))
    bc_display_pred = claims_for(claims_found_pred['claims'])
    print('\n\n== 16 == BC display claims by predicate: {}'.format(ppjson(bc_display_pred)))
    assert len(bc_display_pred) == 1

    # 15. BC Org Book agent (as HolderProver) creates proof by predicate, default req-attrs
    bc_proof_resp_pred = get_post_response(
        cfg['sri']['Agent'],
        'proof-request',
        (
            json.dumps(list_schemata([S_KEY['BC']])),
            json.dumps([]),
            json.dumps([
                pred_match(
                    S_KEY['BC'],
                    [
                        pred_match_match('id', '>=', 2),
                        pred_match_match('orgTypeId', '>=', 2),
                    ]  # resolves to one claim
                )
            ]),
            json.dumps([])
        ),
        agent_profile2did['bc-org-book'])
    print('\n\n== 17 == BC proof by predicates id, orgTypeId >= 2: {}'.format(ppjson(bc_proof_resp_pred)))
    revealed = revealed_attrs(bc_proof_resp_pred['proof'])
    print('\n\n== 18 == BC proof revealed attrs by predicates id, orgTypeId >= 2: {}'.format(ppjson(revealed)))
    assert len(revealed) == 1
    assert (set(revealed[set(revealed.keys()).pop()].keys()) ==
        set(schema_store[S_KEY['BC']]['data']['attr_names']) - set(('id', 'orgTypeId')))

    # 16. SRI agent (as Verifier) verifies proof (by predicates)
    sri_bc_verification_resp = get_post_response(
        cfg['sri']['Agent'],
        'verification-request',
        (
            json.dumps(bc_proof_resp_pred['proof-req']),
            json.dumps(bc_proof_resp_pred['proof'])
        ))
    print('\n\n== 19 == SRI agent verifies BC proof by predicates id, orgTypeId >= 2 as {}'.format(
        ppjson(sri_bc_verification_resp)))
    assert sri_bc_verification_resp

    # 17. Create and store SRI registration completion claims, green claims from verified proof + extra data
    revealed = revealed_attrs(bc_proof_resp['proof'])[bc_referent]
    claim_data[S_KEY['SRI-1.0']].append({
        **{k: revealed[k] for k in revealed if k in schema_store[S_KEY['SRI-1.0']]['data']['attr_names']},
        'sriRegDate': datetime.date.today().strftime('%Y-%m-%d')
    })
    claim_data[S_KEY['SRI-1.1']].append({
        **{k: revealed[k] for k in revealed if k in schema_store[S_KEY['SRI-1.1']]['data']['attr_names']},
        'sriRegDate': datetime.date.today().strftime('%Y-%m-%d'),
        'businessLang': 'EN-CA'
    })
    claim_data[S_KEY['GREEN']].append({
        **{k: revealed[k] for k in revealed if k in schema_store[S_KEY['GREEN']]['data']['attr_names']},
        'greenLevel': 'Silver',
        'auditDate': datetime.date.today().strftime('%Y-%m-%d')
    })

    i = 0
    for s_key in claim_data:
        if s_key == S_KEY['BC']:
            continue
        for c in claim_data[s_key]:
            print('\n\n== 20.{} == Data for SRI claim on [{} v{}]: {}'.format(
                i,
                s_key.name,
                s_key.version,
                ppjson(c)))
            i += 1

    i = 0
    for s_key in claim_data:
        if s_key == S_KEY['BC']:
            continue
        for c in claim_data[s_key]:
            claim[s_key] = get_post_response(
                cfg[schema_key2issuer_agent_profile[s_key]]['Agent'],
                'claim-create',
                (json.dumps(claim_req[s_key]), json.dumps(c)))
            assert claim[s_key]

            print('\n\n== 21.{} == {} claim: {}'.format(i, s_key, ppjson(claim[s_key])))
            get_post_response(
                cfg[schema_key2issuer_agent_profile[s_key]]['Agent'],
                'claim-store',
                (
                    json.dumps(claim[s_key]),
                ),
                agent_profile2did['pspc-org-book'])
            i += 1

    # 18. SRI agent proxies to PSPC Org Book agent (as HolderProver) to find all claims, one schema at a time
    i = 0
    for s_key in claim_data:
        if s_key == S_KEY['BC']:
            continue
        sri_claim = get_post_response(
            cfg['sri']['Agent'],
            'claim-request',
            (
                json.dumps(list_schemata([s_key])),
                json.dumps([]),
                json.dumps([]),
                json.dumps([])
            ),
            agent_profile2did['pspc-org-book'])
        print('\n\n== 22.{}.0 == SRI claims on [{} v{}], no filter: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(sri_claim)))
        assert len(sri_claim['claims']['attrs']) == len(schema_store[s_key]['data']['attr_names'])

        sri_claim = get_post_response(
            cfg['sri']['Agent'],
            'claim-request',
            (
                json.dumps([]),
                json.dumps([attr_match(s_key)]),
                json.dumps([]),
                json.dumps([])
            ),
            agent_profile2did['pspc-org-book'])
        print('\n\n== 22.{}.1 == SRI claims, filter for all attrs in schema [{} v{}]: {}'.format(
            i,
            s_key.name,
            s_key.version,
            ppjson(sri_claim)))
        i += 1
        assert len(sri_claim['claims']['attrs']) == len(schema_store[s_key]['data']['attr_names'])

    # 19. SRI agent proxies to PSPC Org Book agent (as HolderProver) to find all claims, for all schemata, on first attr
    sri_claims_all_first_attr = get_post_response(
        cfg['sri']['Agent'],
        'claim-request',
        (
            json.dumps(list_schemata([s_key for s_key in claim_data if s_key != S_KEY['BC']])),
            json.dumps([]),
            json.dumps([]),
            json.dumps([req_attrs(s_key, [schema_store[s_key]['data']['attr_names'][0]])
                for s_key in claim_data if s_key != S_KEY['BC']])
        ),
        agent_profile2did['pspc-org-book'])

    print('\n\n== 23 == All SRI claims at PSPC Org Book, first attr only: {}'.format(ppjson(sri_claims_all_first_attr)))
    assert len(sri_claims_all_first_attr['claims']['attrs']) == (len(schema_store.index()) - 1)  # all except BC

    # 20. SRI agent proxies to PSPC Org Book agent (as HolderProver) to find all claims, on all schemata at once
    sri_claims_all = get_post_response(
        cfg['sri']['Agent'],
        'claim-request',
        (
            json.dumps(list_schemata([s_key for s_key in claim_data if s_key != S_KEY['BC']])),
            json.dumps([]),
            json.dumps([]),
            json.dumps([])
        ),
        agent_profile2did['pspc-org-book'])
    print('\n\n== 24 == All SRI claims at PSPC Org Book, all attrs: {}'.format(ppjson(sri_claims_all)))
    sri_display = claims_for(sri_claims_all['claims'])
    print('\n\n== 25 == All SRI claims at PSPC Org Book by referent: {}'.format(ppjson(sri_display)))

    # 21. SRI agent proxies to PSPC Org Book agent (as HolderProver) to create (multi-claim) proof
    sri_proof_resp = get_post_response(
        cfg['sri']['Agent'],
        'proof-request',
        (
            json.dumps(list_schemata([s_key for s_key in claim_data if s_key != S_KEY['BC']])),
            json.dumps([]),
            json.dumps([]),
            json.dumps([])
        ),
        agent_profile2did['pspc-org-book'])
    print('\n\n== 26 == PSPC org book proof response on all claims: {}'.format(ppjson(sri_proof_resp)))
    assert len(sri_proof_resp['proof']['proof']['proofs']) == len(sri_display)

    # 22. SRI agent (as Verifier) verifies proof
    sri_verification_resp = get_post_response(
        cfg['sri']['Agent'],
        'verification-request',
        (
            json.dumps(sri_proof_resp['proof-req']),
            json.dumps(sri_proof_resp['proof'])
        ))
    print('\n\n== 27 == SRI agent verifies proof (by empty filter) as {}'.format(
        ppjson(sri_verification_resp)))
    assert sri_verification_resp

    # 23. SRI agent proxies to PSPC Org Book agent (as HolderProver) to create (multi-claim) proof by referent
    sri_proof_resp = get_post_response(
        cfg['sri']['Agent'],
        'proof-request-by-referent',
        (
            json.dumps(list_schemata([s_key for s_key in claim_data if s_key != S_KEY['BC']])),
            json.dumps([referent for referent in sri_display]),
            json.dumps([])
        ),
        agent_profile2did['pspc-org-book'])
    print('\n\n== 28 == PSPC org book proof response on referents {}: {}'.format(
        {referent for referent in sri_display},
        ppjson(sri_proof_resp)))
    assert len(sri_proof_resp['proof']['proof']['proofs']) == len(sri_display)

    # 24. SRI agent (as Verifier) verifies proof
    sri_verification_resp = get_post_response(
        cfg['sri']['Agent'],
        'verification-request',
        (
            json.dumps(sri_proof_resp['proof-req']),
            json.dumps(sri_proof_resp['proof'])
        ))
    print('\n\n== 29 == SRI agent verifies proof on referents {} as {}'.format(
        {referent for referent in sri_display},
        ppjson(sri_verification_resp)))
    assert sri_verification_resp

    # 25. SRI agent proxies to PSPC Org Book agent to create multi-claim proof by ref, schemata implicit, not legalName
    sri_proof_resp = get_post_response(
        cfg['sri']['Agent'],
        'proof-request-by-referent',
        (
            json.dumps([]),
            json.dumps([referent for referent in sri_display]),
            json.dumps([req_attrs(s_key, [a for a in schema_store[s_key]['data']['attr_names'] if a != 'legalName'])
                for s_key in claim_data if s_key != S_KEY['BC']])
        ),
        agent_profile2did['pspc-org-book'])
    print('\n\n== 30 == PSPC org book proof response, schemata implicit, referents {}, not legalName: {}'.format(
        {referent for referent in sri_display},
        ppjson(sri_proof_resp)))
    assert len(sri_proof_resp['proof']['proof']['proofs']) == len(sri_display)
    revealed = revealed_attrs(sri_proof_resp['proof'])
    print('\n\n== 31 == Revealed attrs for above: {}'.format(ppjson(revealed)))
    assert Counter([attr for c in revealed for attr in revealed[c]]) == Counter(
        [attr for s_key in schema_store.index().values() if s_key != S_KEY['BC']
            for attr in schema_store[s_key]['data']['attr_names'] if attr != 'legalName'])

    # 26. SRI agent (as Verifier) verifies proof
    sri_verification_resp = get_post_response(
        cfg['sri']['Agent'],
        'verification-request',
        (
            json.dumps(sri_proof_resp['proof-req']),
            json.dumps(sri_proof_resp['proof'])
        ))
    print('\n\n== 32 == SRI agent verifies proof on referents {} as {}'.format(
        {referent for referent in sri_display},
        ppjson(sri_verification_resp)))
    assert sri_verification_resp

    # 27. SRI agent proxies to PSPC Org Book agent (as HolderProver) to create proof on req-attrs for green schema attrs
    sri_proof_resp = get_post_response(
        cfg['sri']['Agent'],
        'proof-request',
        (
            json.dumps([]),
            json.dumps([]),
            json.dumps([]),
            json.dumps([req_attrs(S_KEY['GREEN'])])
        ),
        agent_profile2did['pspc-org-book'])
    print('\n\n== 33 == PSPC org book proof to green claims response: {}'.format(ppjson(sri_proof_resp)))
    assert {sri_proof_resp['proof-req']['requested_attrs'][k]['name']
        for k in sri_proof_resp['proof-req']['requested_attrs']} == set(    
            schema_store[S_KEY['GREEN']]['data']['attr_names'])

    # 28. SRI agent (as Verifier) verifies proof
    sri_verification_resp = get_post_response(
        cfg['sri']['Agent'],
        'verification-request',
        (
            json.dumps(sri_proof_resp['proof-req']),
            json.dumps(sri_proof_resp['proof'])
        ))
    print('\n\n== 34 == SRI agent verifies proof on [{} v{}] attrs as {}'.format(
        S_KEY['GREEN'].name,
        S_KEY['GREEN'].version,
        ppjson(sri_verification_resp)))
    assert sri_verification_resp

    # 29. Exercise helper GET TXN call
    seq_no = {k for k in schema_store.index().keys()}.pop()  # there will be a real transaction here
    url = url_for(cfg['sri']['Agent'], 'txn/{}'.format(seq_no))
    r = requests.get(url)
    assert r.status_code == 200
    assert r.json()
    print('\n\n== 35 == ledger transaction #{}: {}'.format(seq_no, ppjson(r.json())))
    
    # 30. txn# non-existence case
    url = url_for(cfg['sri']['Agent'], 'txn/99999')
    r = requests.get(url)  # ought not exist
    assert r.status_code == 200
    print('\n\n== 36 == txn #99999: {}'.format(ppjson(r.json())))
    assert not r.json() 
