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

from django.shortcuts import render
from django.contrib.auth.models import User
from django.core.cache import cache
from indy.error import IndyError
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from time import time as epoch
from von_agent.error import VonAgentError
from wrapper_api.eventloop import do

import asyncio
import json
import logging


logger = logging.getLogger(__name__)
path_prefix_slash = '{}/'.format(cache.get('config')['VON Connector']['api.base.url.path'].strip('/'))


class ServiceWrapper(APIView):
    """
    API endpoint accepting requests for current agent
    """

    def post(self, req):
        """
        Wiring for agent POST processing
        """

        ag = cache.get('agent')
        assert ag is not None
        try:
            logger.debug('Processing POST [{}], request body: {}'.format(req.build_absolute_uri(), req.body))
            form = json.loads(req.body.decode('utf-8'))
            rv_json = do(ag.process_post(form))
            return Response(json.loads(rv_json))
        except Exception as e:
            import traceback
            logging.exception('Exception on {}: {}'.format(req.path, e))
            # traceback.print_exc()
            return Response(
                status=400,
                data={
                    'error-code': int(e.error_code) if isinstance(e, (IndyError, VonAgentError)) else 400,
                    'message': str(e)
                })
        finally:
            cache.set('agent', ag)  #  in case agent state changes over process_post

    def get(self, req, seq_no=None):
        """
        Wiring for agent helper (GET) methods
        """

        ag = cache.get('agent')
        assert ag is not None
        try:
            logger.debug('Processing GET [{}]'.format(req.build_absolute_uri()))
            if req.path.startswith('/{}txn'.format(path_prefix_slash)):
                rv_json = do(ag.process_get_txn(int(seq_no)))
                return Response(json.loads(rv_json))
            elif req.path.startswith('/{}did'.format(path_prefix_slash)):
                rv_json = do(ag.process_get_did())
                return Response(json.loads(rv_json))
            else:
                raise NotFound(detail='Error 404, page not found', code=404)
        except Exception as e:
            return Response(
                status=400,
                data={
                    'error-code': int(e.error_code) if isinstance(e, (IndyError, VonAgentError)) else 400,
                    'message': str(e)
                })
