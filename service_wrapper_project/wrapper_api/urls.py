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

from django.conf import settings
from django.conf.urls import url, include
from django.core.cache import cache
from wrapper_api import views
from rest_framework import routers, serializers, viewsets


urlpatterns = [
    url(
        r'^{}'.format('{}/'.format(cache.get('config')['VON Connector']['api.base.url.path'].strip('/'))),
        include([
            url(r'^txn/(?P<seq_no>\d+)', views.ServiceWrapper.as_view()),
            url(r'^did', views.ServiceWrapper.as_view()),

            # redundant patterns here show explicitly what service wrapper takes as POSTed tokens
            url(r'^agent-nym-lookup', views.ServiceWrapper.as_view()),
            url(r'^agent-nym-send', views.ServiceWrapper.as_view()),
            url(r'^agent-endpoint-lookup', views.ServiceWrapper.as_view()),
            url(r'^agent-endpoint-send', views.ServiceWrapper.as_view()),
            url(r'^schema-send', views.ServiceWrapper.as_view()),
            url(r'^schema-lookup', views.ServiceWrapper.as_view()),
            url(r'^claim-def-send', views.ServiceWrapper.as_view()),
            url(r'^master-secret-set', views.ServiceWrapper.as_view()),
            url(r'^claim-offer-create', views.ServiceWrapper.as_view()),
            url(r'^claim-offer-store', views.ServiceWrapper.as_view()),
            url(r'^claim-create', views.ServiceWrapper.as_view()),
            url(r'^claim-store', views.ServiceWrapper.as_view()),
            url(r'^claim-request', views.ServiceWrapper.as_view()),
            url(r'^proof-request', views.ServiceWrapper.as_view()),
            url(r'^proof-request-by-referent', views.ServiceWrapper.as_view()),
            url(r'^verification-request', views.ServiceWrapper.as_view()),
            url(r'^claims-reset', views.ServiceWrapper.as_view()),
        ])
    ),
]

"""
# Noodling for static swagger ui proof of concept, known to be deficient in its monolithic base url
stat = staticfiles_urlpatterns()

print('\n\n -- len: {}'.format(len(stat)))
for s in stat:
    print('*** Static URL pattern: {}'.format(s.regex.pattern))
urlpatterns += stat
"""

"""
urlpatterns += staticfiles_urlpatterns()  # hacky, requires DEBUG
"""
