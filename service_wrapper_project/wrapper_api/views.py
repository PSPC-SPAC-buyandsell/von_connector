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

from django.shortcuts import render
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from time import time as epoch
from wrapper_api.eventloop import do
from wrapper_api.apps import PATH_PREFIX_SLASH
from indy.error import IndyError

import asyncio
import json
import logging


logger = logging.getLogger(__name__)


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
            form = json.loads(req.body.decode("utf-8"))
            rv_json = do(ag.process_post(form))
            return Response(json.loads(rv_json))  # FIXME: this only loads it to dump it: it's already json
        except Exception as e:
            import traceback
            logging.exception('Exception on {}: {}'.format(req.path, e))
            # traceback.print_exc()
            return Response(
                status=500,
                data={
                    'error-code': e.error_code if isinstance(e, IndyError) else 500,
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
            if req.path.startswith('/{}txn'.format(PATH_PREFIX_SLASH)):
                rv_json = do(ag.process_get_txn(int(seq_no)))
                return Response(json.loads(rv_json))
            elif req.path.startswith('/{}did'.format(PATH_PREFIX_SLASH)):
                rv_json = do(ag.process_get_did())
                return Response(json.loads(rv_json))
            else:
                raise ValueError(
                    'Agent service wrapper API does not respond on GET to URL on path {}'.format(req.path))
        except Exception as e:
            return Response(
                status=500,
                data={
                    'error-code': e.error_code if isinstance(e, IndyError) else 500,
                    'message': str(e)
                })
