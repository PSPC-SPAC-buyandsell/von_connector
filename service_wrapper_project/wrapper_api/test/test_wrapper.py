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
from contextlib import closing
from os import walk
from os.path import abspath, dirname, isfile, join as pjoin
from time import sleep
from von_agent.util import ppjson, claims_for, encode, prune_claims_json, revealed_attrs

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
            'claim-request-by-claim-uuid',
            'proof-request-by-claim-uuid',
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


def claim_req_for(schema, claim_req, claim):
    # walk the schemata to find schema whose attrs match the claim; get corresponding claim_req
    for origin_ag in schema:
        for name in schema[origin_ag]:
            for version in schema[origin_ag][name]:
                if set(schema[origin_ag][name][version]['data']['attr_names']) == set([*claim]):
                    return claim_req[origin_ag][name][version]
    return None


def schema_key_values_for(schema, claim):
    # walk the schemata to find and return first (origin did, name, version) matching input claim
    for origin_ag in schema:
        for name in schema[origin_ag]:
            for version in schema[origin_ag][name]:
                if set([*claim]).issubset(schema[origin_ag][name][version]['data']['attr_names']):
                    return (schema[origin_ag][name][version]['data']['origin'], name, version)
    return None


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
    did = {}
    for agent_profile in agent_profiles:
        url = url_for(cfg[agent_profile]['Agent'], 'did')
        # print('\n... url {}'.format(url))
        r = requests.get(url)
        # print('\n... done req\n')
        assert r.status_code == 200
        did[agent_profile] = r.json()
    # trust-anchor: V4SGRU86Z58d6TV7PBUe6f
    # sri: FaBAq1W5QTVDpAZtep6h19
    # bc-org-book: Rzra4McufsSNUQ1mGyWc2w
    # pspc-org-book: 45UePtKtVrZ6UycN9gmMsG
    # bc-registrar: Q4zqM7aXqm7gDQkUVLng9h
    print('\n\n== 3 == DIDs: {}'.format(ppjson(did)))

    # 3. get schemata
    schema = {}
    for ag in agent_profiles:
        if 'Origin' not in cfg[ag]:
            continue
        if ag not in schema:
            schema[ag] = {}
        for name in cfg[ag]['Origin']:  # read each schema once - each schema has one originator
            if name not in schema[ag]:
                schema[ag][name] = {}
            for version in (v.strip() for v in cfg[ag]['Origin'][name].split(',')):
                schema_lookup_json = form_json(
                    'schema-lookup',
                    (
                        did[ag],
                        name,
                        version
                    ))

                url = url_for(cfg[ag]['Agent'], 'schema-lookup')
                r = requests.post(url, json=json.loads(schema_lookup_json))
                assert r.status_code == 200
                schema[ag][name][version] = r.json()
    print('\n\n== 4 == Schemata: {}'.format(ppjson(schema)))

    # 4. BC Org Book, PSPC Org Book (as HolderProvers) respond to claims-reset directive, to restore state to base line
    claims_reset_json = form_json(
        'claims-reset',
        ())
    for profile in ('bc-org-book', 'pspc-org-book'):
        url = url_for(cfg[profile]['Agent'], 'claims-reset')
        r = requests.post(url, json=json.loads(claims_reset_json))
        assert r.status_code == 200
        reset_resp = r.json()
        assert not reset_resp

    # 5. Issuers send claim-hello to HolderProvers
    claim_req = {}
    for origin_ag in schema:
        if origin_ag not in claim_req:
            claim_req[origin_ag] = {}
        for name in schema[origin_ag]:
            if name not in claim_req[origin_ag]:
                claim_req[origin_ag][name] = {}
            for version in schema[origin_ag][name]:
                claim_hello_json = form_json(
                    'claim-hello',
                    (did[origin_ag], did[origin_ag], name, version),
                    did['bc-org-book'] if origin_ag == 'bc-registrar' else did['pspc-org-book'])
                url = url_for(
                    cfg['bc-registrar']['Agent'] if origin_ag == 'bc-registrar' else cfg['sri']['Agent'],
                    'claim-hello')

                # print('\n\n== XX == attempt to POST to url {}: {}'.format(url, ppjson(claim_hello_json)))
                r = requests.post(url, json=json.loads(claim_hello_json))
                assert r.status_code == 200
                claim_req[origin_ag][name][version] = r.json()
                assert claim_req[origin_ag][name][version]
    print('\n\n== 5 == Claim requests: {}'.format(ppjson(claim_req)))

    # 6. BC Registrar creates claims and stores at BC Org Book (as HolderProver)
    bc_claims = [
        {
            'id': 1,
            'busId': 11121398,
            'orgTypeId': 2,
            'jurisdictionId': 1,
            'legalName': 'The Original House of Pies',
            'effectiveDate': '2010-10-10',
            'endDate': None
        },
        {
            'id': 2,
            'busId': 11133333,
            'orgTypeId': 1,
            'jurisdictionId': 1,
            'legalName': 'Planet Cake',
            'effectiveDate': '2011-10-01',
            'endDate': None
        },
        {
            'id': 3,
            'busId': 11144444,
            'orgTypeId': 2,
            'jurisdictionId': 1,
            'legalName': 'Tart City',
            'effectiveDate': '2012-12-01',
            'endDate': None
        }
    ]
    for c in bc_claims:
        bc_claim_create_json = form_json(
            'claim-create',
            (json.dumps(claim_req_for(schema, claim_req, c)),
            json.dumps(c)))
        url = url_for(cfg['bc-registrar']['Agent'], 'claim-create')
        r = requests.post(url, json=json.loads(bc_claim_create_json))
        assert r.status_code == 200
        bc_claim = r.json()
        assert bc_claim

        print('\n\n== 6.{} == BC claim: {}'.format(bc_claims.index(c), ppjson(bc_claim)))
        bc_claim_store_json = form_json(
            'claim-store',
            (json.dumps(bc_claim),),
            did['bc-org-book'])
        url = url_for(cfg['bc-registrar']['Agent'], 'claim-store')
        r = requests.post(url, json=json.loads(bc_claim_store_json))
        assert r.status_code == 200
        # response is empty

    # 7. SRI agent proxies to BC Org Book (as HolderProver) to find claims
    bc_schema_key_values = schema_key_values_for(
        schema,
        bc_claims[2])  # for our test case, BC uses exactly one version of one schema
    bc_claim_req_all_json = form_json(
        'claim-request',
        (
            *bc_schema_key_values,
            json.dumps({})
        ),
        did['bc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'claim-request')
    r = requests.post(url, json=json.loads(bc_claim_req_all_json))
    assert r.status_code == 200
    bc_claims_all = r.json()
    print('\n\n== 7 == BC claims by attr, no filter: {}'.format(ppjson(bc_claims_all)))
    assert bc_claims_all

    bc_display_pruned_postfilt = claims_for(bc_claims_all['claims'], {'legalName': bc_claims[2]['legalName']})
    print('\n\n== 8 == BC display claims filtered post-hoc matching {}: {}'.format(
        bc_claims[2]['legalName'],
        ppjson(bc_display_pruned_postfilt)))
    bc_display_pruned = prune_claims_json({k for k in bc_display_pruned_postfilt}, bc_claims_all['claims'])
    print('\n\n== 9 == BC claims stripped down {}'.format(ppjson(bc_display_pruned)))

    bc_claim_req_prefilt_json = form_json(
        'claim-request',
        (
            *bc_schema_key_values,
            json.dumps({k: bc_claims[2][k] for k in bc_claims[2] if k in ('jurisdictionId', 'busId')})
        ),
        did['bc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'claim-request')
    r = requests.post(url, json=json.loads(bc_claim_req_prefilt_json))
    assert r.status_code == 200
    bc_claims_prefilt = r.json()
    assert bc_claims_prefilt

    print('\n\n== 10 == BC claims by attr, filtered a priori {}'.format(ppjson(bc_claims_prefilt)))
    bc_display_pruned_prefilt = claims_for(bc_claims_prefilt['claims'])
    print('\n\n== 11 == BC display claims filtered a priori matching {}: {}'.format(
        bc_claims[2]['legalName'],
        ppjson(bc_display_pruned_prefilt)))
    assert set([*bc_display_pruned_postfilt]) == set([*bc_display_pruned_prefilt])
    assert len(bc_display_pruned_postfilt) == 1

    # 8. BC Org Book (as HolderProver) creates proof and responds to request for proof (by filter)
    bc_claim_uuid = set([*bc_display_pruned_prefilt]).pop()
    bc_proof_req_json = form_json(
        'proof-request',
        (
            *bc_schema_key_values,
            json.dumps({k: bc_claims[2][k] for k in bc_claims[2] if k in ('jurisdictionId', 'busId')})
        ),
        did['bc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'proof-request')
    r = requests.post(url, json=json.loads(bc_proof_req_json))
    assert r.status_code == 200
    bc_proof_resp = r.json()
    print('\n\n== 12 == BC proof (req by filter): {}'.format(ppjson(bc_proof_resp)))
    assert bc_proof_resp

    # 9. SRI Agent (as Verifier) verifies proof (by filter)
    bc_verification_req_json = form_json(
        'verification-request',
        (
            *bc_schema_key_values,
            json.dumps(bc_proof_resp['proof-req']),json.dumps(bc_proof_resp['proof'])
        ))
    url = url_for(cfg['sri']['Agent'], 'verification-request')
    r = requests.post(url, json=json.loads(bc_verification_req_json))
    assert r.status_code == 200
    bc_verification_resp = r.json()
    print('\n\n== 13 == SRI agent verifies BC proof (by filter) as {}'.format(ppjson(bc_verification_resp)))
    assert bc_verification_resp

    # 10. BC Org Book (as HolderProver) creates proof and responds to request for proof (by claim-uuid)
    bc_proof_req_json_by_uuid = form_json(
        'proof-request-by-claim-uuid',
        (
            *bc_schema_key_values,
            bc_claim_uuid
        ),
        did['bc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'proof-request-by-claim-uuid')
    r = requests.post(url, json=json.loads(bc_proof_req_json_by_uuid))
    assert r.status_code == 200
    bc_proof_resp = r.json()
    assert bc_proof_resp

    bc_proof_req_json_by_non_uuid = form_json(
        'proof-request-by-claim-uuid',
        (
            *bc_schema_key_values,
            'claim::ffffffff-ffff-ffff-ffff-ffffffffffff'
        ),
        did['bc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'proof-request-by-claim-uuid')
    r = requests.post(url, json=json.loads(bc_proof_req_json_by_non_uuid))
    assert r.status_code == 500

    # 11. SRI Agent (as Verifier) verifies proof (by uuid)
    sri_bc_verification_req_json = form_json(
        'verification-request',
        (
            *bc_schema_key_values,
            json.dumps(bc_proof_resp['proof-req']),
            json.dumps(bc_proof_resp['proof'])
        ))
    url = url_for(cfg['sri']['Agent'], 'verification-request')
    r = requests.post(url, json=json.loads(sri_bc_verification_req_json))
    assert r.status_code == 200
    sri_bc_verification_resp = r.json()
    print('\n\n== 14 == SRI agent verifies BC proof (by claim-uuid={}) as {}'.format(
        bc_claim_uuid,
        ppjson(sri_bc_verification_resp)))
    assert sri_bc_verification_resp

    # 12. SRI agent (as Issuer) creates SRI reg completion claim from proof, stores at PSPC Org Book (as HolderProver)
    revealed = revealed_attrs(bc_proof_resp['proof'])
    # print('\n\n== XX == Revealed attributes: {}'.format(ppjson(revealed)));
    sri_schema_key_values = schema_key_values_for(schema, {'sriRegDate': None})
    (_, sri_schema_name, sri_schema_version) = sri_schema_key_values
    sri_claim = {k: claim_value_pair(revealed[k]) for k in revealed
        if k in schema['sri'][sri_schema_name][sri_schema_version]['data']['attr_names']}
    yyyy_mm_dd = datetime.date.today().strftime('%Y-%m-%d')
    sri_claim['sriRegDate'] = claim_value_pair(yyyy_mm_dd)
    print('\n\n== 15 == revealed attributes from proof, augmented with SRI data: {}'.format(ppjson(sri_claim)))

    sri_claim_create_json = form_json(
        'claim-create',
        (
            json.dumps(claim_req_for(schema, claim_req, sri_claim)),
            json.dumps(sri_claim)
        ))
    url = url_for(cfg['sri']['Agent'], 'claim-create')
    r = requests.post(url, json=json.loads(sri_claim_create_json))
    assert r.status_code == 200
    sri_claim = r.json()
    print('\n\n== 16 == SRI claim as returned from claim-create: {}'.format(ppjson(sri_claim)))
    assert sri_claim

    sri_claim_store_json = form_json(
        'claim-store',
        (
            json.dumps(sri_claim),
        ),
        did['pspc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'claim-store')
    r = requests.post(url, json=json.loads(sri_claim_store_json))
    assert r.status_code == 200
    # response is empty

    # 13. PSPC Org Book (as HolderProver) finds claims
    sri_claim_req_all_json = form_json(
        'claim-request',
        (
            *sri_schema_key_values,
            json.dumps({})
        ),
        did['pspc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'claim-request')
    r = requests.post(url, json=json.loads(sri_claim_req_all_json))
    assert r.status_code == 200
    sri_claims_all = r.json()
    print('\n\n== 17 == SRI claims-all: {}'.format(ppjson(sri_claims_all)))
    assert sri_claims_all

    # 14. PSPC Org Book (as HolderProver) creates proof (by claim-uuid)
    sri_display = claims_for(sri_claims_all['claims'])
    assert len(sri_display) == 1
    sri_claim_uuid = set([*sri_display]).pop()
    sri_proof_req_json_by_uuid = form_json(
        'proof-request-by-claim-uuid',
        (
            *sri_schema_key_values,
            sri_claim_uuid
        ),
        did['pspc-org-book'])
    url = url_for(cfg['sri']['Agent'], 'proof-request-by-claim-uuid')
    r = requests.post(url, json=json.loads(sri_proof_req_json_by_uuid))
    assert r.status_code == 200
    sri_proof_resp = r.json()
    assert sri_proof_resp

    # 15. SRI (as Verifier) verifies proof (by uuid)
    sri_verification_req_json = form_json(
        'verification-request',
        (
            *sri_schema_key_values,
            json.dumps(sri_proof_resp['proof-req']),
            json.dumps(sri_proof_resp['proof'])
        ))
    url = url_for(cfg['sri']['Agent'], 'verification-request')
    r = requests.post(url, json=json.loads(sri_verification_req_json))
    assert r.status_code == 200
    sri_verification_resp = r.json()
    print('\n\n== 18 == the SRI proof (by claim-uuid={}) verifies as {}'.format(
        sri_claim_uuid,
        ppjson(sri_verification_resp)))
    assert sri_verification_resp

    # 16. Exercise helper GET TXN call
    sri_schema_txn_no = schema['sri'][sri_schema_name][sri_schema_version]['seqNo']
    url = url_for(cfg['sri']['Agent'], 'txn/{}'.format(sri_schema_txn_no))
    r = requests.get(url)
    assert r.status_code == 200
    assert r.json()
    print('\n\n== 19 == ledger transaction #{}: {}'.format(sri_schema_txn_no, ppjson(r.json())))
    
    # 17. txn# non-existence case
    url = url_for(cfg['sri']['Agent'], 'txn/99999')
    r = requests.get(url)  # ought not exist
    assert r.status_code == 200
    print('\n\n== 20 == txn #99999: {}'.format(ppjson(r.json())))
    assert not r.json() 
