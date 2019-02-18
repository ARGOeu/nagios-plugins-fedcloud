import os
import sys
import re
import socket
import requests
import json
from time import sleep

from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from OpenSSL.SSL import VERIFY_PEER
from OpenSSL.SSL import Error as SSLError
from OpenSSL.SSL import WantReadError as SSLWantReadError
from urlparse import urlparse

strerr = ''
num_excp_expand = 0

class AuthenticationException(Exception):
    pass

def nagios_out(status, msg, retcode):
    sys.stdout.write(status+": "+msg+"\n")
    sys.exit(retcode)


def get_keystone_oidc_unscoped_token(parsed_url, suffix, timeout, token,
                                     identity_provider='egi.eu', protocol='openid'):
    try:
        auth_url = ('/v3/OS-FEDERATION/identity_providers/%s/protocols/%s/auth'
                    % (identity_provider, protocol))
        oidc_suffix = suffix + auth_url

        headers = {}

        headers.update({'Authorization': 'Bearer ' + token})
        headers.update({'accept': 'application/json'})
        response = requests.post(parsed_url.scheme+'://'+parsed_url.netloc+oidc_suffix,
                                 headers=headers, timeout=timeout,
                                 verify=True)
        response.raise_for_status()
        return response.headers['X-Subject-Token']
    except(KeyError, IndexError) as e:
        raise AuthenticationException('Could not fetch unscoped keystone token from response: Key not found %s' % errmsg_from_excp(e))
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise AuthenticationException('Connection error %s - %s' % (parsed_url.netloc+oidc_suffix, errmsg_from_excp(e)))


def get_keystone_x509_unscoped_token(parsed_url, suffix, timeout, userca,
                                     identity_provider='egi.eu', protocol='mapped'):
    try:

        auth_url = ('/v3/OS-FEDERATION/identity_providers/%s/protocols/%s/auth'
                    % (identity_provider, protocol))
        token_suffix = suffix + auth_url

        headers = {}

        headers.update({'accept': 'application/json'})

        response = requests.post(parsed_url.scheme+'://'+ parsed_url.netloc + token_suffix, headers=headers,
                                 cert=userca, verify=True, timeout=timeout)

        response.raise_for_status()
        return response.headers['X-Subject-Token']
    except(KeyError, IndexError) as e:
        raise AuthenticationException('Could not fetch unscoped keystone token from response: Key not found %s' % errmsg_from_excp(e))
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise AuthenticationException('Connection error %s - %s' % (parsed_url.netloc+token_suffix, errmsg_from_excp(e)))


def get_keystone_v3_token(unscoped_token_getter, host, timeout, **kwargs):
    o = urlparse(host)
    if o.scheme != 'https':
        raise AuthenticationException('Connection error %s - Probe expects HTTPS endpoint' % (o.scheme+'://'+o.netloc))

    suffix = o.path.rstrip('/')
    if suffix.endswith('v2.0') or suffix.endswith('v3'):
        suffix = os.path.dirname(suffix)

    token = unscoped_token_getter(o, suffix, timeout, **kwargs)

    try:
        # use unscoped token to get a list of allowed projects mapped to
        # ops VO from atuh token
        project_suffix = suffix + '/v3/auth/projects'

        headers = {'content-type': 'application/json', 'accept': 'application/json'}
        headers.update({'x-auth-token': token})
        response = requests.get(o.scheme+'://'+o.netloc+project_suffix, headers=headers,
                                data=None, timeout=timeout, verify=True)
        response.raise_for_status()
        projects = response.json()['projects']
        project = {}
        for p in projects:
            if 'ops' in p['name']:
                project = p
                break
        else:
            # just take one
            project = projects.pop()
    except(KeyError, IndexError) as e:
        raise AuthenticationException('Could not fetch allowed projects from response: Key not found %s' % errmsg_from_excp(e))
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise AuthenticationException('Connection error %s - %s' % (o.scheme+'://'+o.netloc+project_suffix, errmsg_from_excp(e)))

    try:
        # get scoped token for allowed project
        token_suffix = suffix + '/v3/auth/tokens'
        headers = {'content-type': 'application/json', 'accept': 'application/json'}
        payload = {"auth": {"identity": {"methods": ["token"], "token": {"id": token}},
                            "scope": {"project": {"id": project["id"]}}}}
        response = requests.post(o.scheme+'://'+o.netloc+token_suffix, headers=headers,
                                data=json.dumps(payload), verify=True, timeout=timeout)
        response.raise_for_status()
        token = response.headers['X-Subject-Token']
    except(KeyError, IndexError) as e:
        raise AuthenticationException('Could not fetch scoped keystone token for %s from response: Key not found %s' % (project, errmsg_from_excp(e)))
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise AuthenticationException('Connection error %s - %s' % (o.scheme+'://'+o.netloc+token_suffix, errmsg_from_excp(e)))

    return token, project, response

def get_keystone_token_oidc_v3(host, timeout, **kwargs):
    return get_keystone_v3_token(get_keystone_oidc_unscoped_token, host, timeout, **kwargs)

def get_keystone_token_x509_v3(host, timeout, **kwargs):
    return get_keystone_v3_token(get_keystone_x509_unscoped_token, host, timeout, **kwargs)

def get_keystone_token_x509_v2(host, timeout, userca=None):
    o = urlparse(host)
    if o.scheme != 'https':
        raise AuthenticationException('Connection error %s - Probe expects HTTPS endpoint' % (o.scheme+'://'+o.netloc))
    try:
        # fetch unscoped token
        token_suffix = o.path.rstrip('/') + '/tokens'

        headers, payload, token = {}, {}, None
        headers.update({'Accept': '*/*'})

        headers = {'content-type': 'application/json', 'accept': 'application/json'}
        payload = {'auth': {'voms': True}}
        response = requests.post(o.scheme+'://'+o.netloc+token_suffix, headers=headers,
                                data=json.dumps(payload), cert=userca, verify=True, timeout=timeout)
        response.raise_for_status()
        token = response.json()['access']['token']['id']
    except(KeyError, IndexError) as e:
        raise AuthenticationException('Could not fetch unscoped keystone token from response: Key not found %s' % errmsg_from_excp(e))
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise AuthenticationException('Connection error %s - %s' % (o.netloc+token_suffix, errmsg_from_excp(e)))

    try:
        # use unscoped token to get a list of allowed tenants mapped to
        # ops VO from VOMS proxy cert
        tenant_suffix = o.path.rstrip('/') + '/tenants'

        headers = {'content-type': 'application/json', 'accept': 'application/json'}
        headers.update({'x-auth-token': token})
        response = requests.get(o.scheme+'://'+o.netloc+tenant_suffix, headers=headers,
                                data=None, cert=userca, verify=True, timeout=timeout)
        response.raise_for_status()
        tenants = response.json()['tenants']
        tenant = ''
        for t in tenants:
            if 'ops' in t['name']:
                tenant = t['name']
                break
        else:
            # just take one
            tenant = tenants.pop()['name']
    except(KeyError, IndexError) as e:
        raise AuthenticationException('Could not fetch allowed tenants from response: Key not found %s' % errmsg_from_excp(e))
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise AuthenticationException('Connection error %s - %s' % (o.scheme+'://'+o.netloc+tenant_suffix, errmsg_from_excp(e)))

    try:
        # get scoped token for allowed tenant
        headers = {'content-type': 'application/json', 'accept': 'application/json'}
        payload = {'auth': {'voms': True, 'tenantName': tenant}}
        response = requests.post(o.scheme+'://'+o.netloc+token_suffix, headers=headers,
                                data=json.dumps(payload), cert=userca, verify=True, timeout=timeout)
        response.raise_for_status()
        token = response.json()['access']['token']['id']
    except(KeyError, IndexError) as e:
        raise AuthenticationException('Could not fetch scoped keystone token for %s from response: Key not found %s' % (tenant, errmsg_from_excp(e)))
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise AuthenticationException('Connection error %s - %s' % (o.scheme+'://'+o.netloc+token_suffix, errmsg_from_excp(e)))

    return token, tenant, response

def errmsg_from_excp(e, level=5):
    global strerr, num_excp_expand
    if isinstance(e, Exception) and getattr(e, 'args', False):
        num_excp_expand += 1
        if not errmsg_from_excp(e.args):
            return strerr
    elif isinstance(e, dict):
        for s in e.iteritems():
            errmsg_from_excp(s)
    elif isinstance(e, list):
        for s in e:
            errmsg_from_excp(s)
    elif isinstance(e, tuple):
        for s in e:
            errmsg_from_excp(s)
    elif isinstance(e, str):
        if num_excp_expand <= level:
            strerr += e + ' '
