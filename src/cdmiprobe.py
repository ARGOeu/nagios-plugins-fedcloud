#!/usr/bin/python

# Copyright (C) 2015 SRCE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import argparse, re, random
import requests, sys, os, json, time

from nagios_plugins_fedcloud import helpers

HEADER_CDMI_VERSIONS = [{'X-CDMI-Specification-Version': '1.0.2'}, {'X-CDMI-Specification-Version': '1.0.1'}]
CDMI_CONTAINER = 'application/cdmi-container'
CDMI_CAPABILITIES = 'application/cdmi-capabilities'
CDMI_OBJECT = 'application/cdmi-object'
CDMI_QUEUE = 'application/cdmi-queue'

CONTAINER = '/container-probe'
DOBJECT = '/dataobject-probe'

OPWAIT = 2

DEFAULT_PORT = 443

def keystone_url(server, userca, capath, timeout, cdmiver):
    try:
        # initiate unauthorized response (HTTP 401) with keystone URL
        headers = {}
        headers.update(cdmiver)
        headers.update({'Accept': '*/*'})
        response = requests.get(server, headers=headers, cert=userca, verify=False, timeout=timeout)
        if response.status_code == 400:
            response = requests.get(server, headers={}, cert=userca, verify=False)
    except requests.exceptions.ConnectionError as e:
        helpers.nagios_out('Critical', 'Connection error %s - %s' % (server, helpers.errmsg_from_excp(e)), 2)

    try:
        # extract public keystone URL from response
        keystone_server = re.search("Keystone.*=[\s'\"]*([\w:/\-_\.]*)[\s*\'\"]*", response.headers['www-authenticate']).group(1)
        if ':5000' not in keystone_server:
            raise AttributeError
    except(KeyError, IndexError, AttributeError):
        raise Exception('Could not fetch keystone server from response: Key not found %s' % helpers.errmsg_from_excp(e))

    return keystone_server


def create_container(argholder, ks_token, cdmiver, container_name):
    # create container
    headers = {}
    headers.update(cdmiver)
    headers.update({'accept': CDMI_CONTAINER,
                    'content-type': CDMI_CONTAINER})
    headers.update({'x-auth-token': ks_token})
    response = requests.put(argholder.endpoint + container_name + '/',
                            headers=headers, cert=argholder.cert, verify=False)
    response.raise_for_status()


def delete_container(argholder, ks_token, cdmiver, container_name):
    # remove container
    headers = {}
    headers.update(cdmiver)
    headers.update({'x-auth-token': ks_token})
    response = requests.delete(argholder.endpoint + container_name + '/',
                            headers=headers, cert=argholder.cert, verify=False)
    response.raise_for_status()


def create_dataobject(argholder, ks_token, cdmiver, container_name, obj_name,
                      obj_data):
    # create data object
    headers, payload= {}, {}
    headers.update(cdmiver)
    headers.update({'accept': CDMI_OBJECT,
                    'content-type': CDMI_OBJECT})
    headers.update({'x-auth-token': ks_token})
    payload = {'mimetype': 'text/plain'}
    payload['value'] = unicode(obj_data)
    payload['valuetransferencoding'] = 'utf-8'
    response = requests.put(argholder.endpoint + container_name + obj_name,
                            data=json.dumps(payload), headers=headers,
                            cert=argholder.cert, verify=False)
    response.raise_for_status()


def get_dataobject(argholder, ks_token, cdmiver, container_name, obj_name):
    # get data object
    headers = {}
    headers.update(cdmiver)
    headers.update({'accept': CDMI_OBJECT,
                    'content-type': CDMI_OBJECT})
    headers.update({'x-auth-token': ks_token})
    response = requests.get(argholder.endpoint + container_name + obj_name,
                            headers=headers, cert=argholder.cert, verify=False)
    response.raise_for_status()
    return response.json()['value']


def delete_dataobject(argholder, ks_token, cdmiver, container_name, obj_name):
    # remove data object
    headers = {}
    headers.update(cdmiver)
    headers.update({'x-auth-token': ks_token})
    response = requests.delete(argholder.endpoint + container_name + obj_name,
                               headers=headers, cert=argholder.cert, verify=False)
    response.raise_for_status()


def clean_up(argholder, ks_token, cdmiver, container_name, obj_name=None):
    if obj_name:
        try:
            delete_dataobject(argholder, ks_token, cdmiver,
                              container_name, obj_name)
        except requests.exceptions.HTTPError as e:
            sys.stderr.write('Clean up error: %s\n' % helpers.errmsg_from_excp(e))
    try:
        delete_container(argholder, ks_token, cdmiver, container_name)
    except requests.exceptions.HTTPError as e:
        sys.stderr.write('Clean up error: %s\n' % helpers.errmsg_from_excp(e))


def main():
    class ArgHolder(object):
        pass
    argholder = ArgHolder()

    argnotspec = []
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', dest='endpoint', nargs='?')
    parser.add_argument('--cert', dest='cert', nargs='?')
    parser.add_argument('-t', dest='timeout', type=int, nargs='?', default=120)
    parser.add_argument('--capath', dest='capath', nargs='?', default='/etc/grid-security/certificates')

    parser.parse_args(namespace=argholder)

    for arg in ['endpoint', 'cert', 'capath', 'timeout']:
        if eval('argholder.'+arg) == None:
            argnotspec.append(arg)

    if len(argnotspec) > 0:
        msg_error_args = ''
        for arg in argnotspec:
            msg_error_args += '%s ' % (arg)
        helpers.nagios_out('Unknown', 'command-line arguments not specified, '+msg_error_args, 3)
    else:
        if not argholder.endpoint.startswith("http") \
                or not os.path.isfile(argholder.cert) \
                or not type(argholder.timeout) == int \
                or not os.path.isdir(argholder.capath):
            helpers.nagios_out('Unknown', 'command-line arguments are not correct', 3)

    if helpers.verify_cert(argholder.endpoint, argholder.capath, argholder.timeout, cncheck=False):
        ver = None
        for v, cdmiver in enumerate(HEADER_CDMI_VERSIONS):
            # fetch scoped token for ops VO
            try:
                keystone_server = keystone_url(argholder.endpoint,
                                               argholder.cert,
                                               argholder.capath,
                                               argholder.timeout, cdmiver)
                ks_token = helpers.get_keystone_token(keystone_server,
                                                      argholder.cert,
                                                      argholder.capath,
                                                      argholder.timeout)[0]

            except Exception as e:
                if v == len(HEADER_CDMI_VERSIONS) - 1:
                    helpers.nagios_out('Critical', e.message, 2)

        # if we successfully fetched token, then we also have
        # supported CDMI Specification version
        ver = cdmiver

        randstr = '-'+''.join(random.sample('abcdefghijklmno', 3))
        container_name = CONTAINER + randstr
        randdata = ''.join(random.sample('abcdefghij1234567890', 20))
        obj_name = DOBJECT + randstr

        try:
            create_container(argholder, ks_token, ver, container_name)
        except requests.exceptions.HTTPError as e:
            helpers.nagios_out('Critical', 'test - create_container failed %s' % helpers.errmsg_from_excp(e), 2)

        try:
            create_dataobject(argholder, ks_token, ver, container_name,
                              obj_name, randdata)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name)
            helpers.nagios_out('Critical', 'test - create_dataobject failed %s' % helpers.errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            data = get_dataobject(argholder, ks_token, ver, container_name,
                                  obj_name)
            if data != randdata:
                raise requests.exceptions.HTTPError('data integrity violated')
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            helpers.nagios_out('Critical', 'test - get_dataobject failed %s' % helpers.errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        newranddata = ''.join(random.sample('abcdefghij1234567890', 20))

        try:
            create_dataobject(argholder, ks_token, ver, container_name,
                              obj_name, newranddata)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            helpers.nagios_out('Critical', 'test - update_dataobject failed %s' % helpers.errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            data = get_dataobject(argholder, ks_token, ver, container_name,
                                  obj_name)
            if data != newranddata:
                raise requests.exceptions.HTTPError('data integrity violated')
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            helpers.nagios_out('Critical', 'test - get_dataobject failed %s' % helpers.errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            delete_dataobject(argholder, ks_token, ver, container_name,
                              obj_name)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            helpers.nagios_out('Critical', 'test - delete_dataobject failed %s' % helpers.errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            delete_container(argholder, ks_token, ver, container_name)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            helpers.nagios_out('Critical', 'test - delete_container failed %s' % helpers.errmsg_from_excp(e), 2)

        helpers.nagios_out('OK', 'container and dataobject creating, fetching and removing tests were successful', 0)

main()
