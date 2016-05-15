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


import argparse, re, random, signal
import requests, sys, os, json, socket, time

from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from OpenSSL.SSL import Error as SSLError

HEADER_CDMI_VERSIONS = [{'X-CDMI-Specification-Version': '1.0.2'}, {'X-CDMI-Specification-Version': '1.0.1'}]
CDMI_CONTAINER = 'application/cdmi-container'
CDMI_CAPABILITIES = 'application/cdmi-capabilities'
CDMI_OBJECT = 'application/cdmi-object'
CDMI_QUEUE = 'application/cdmi-queue'

CONTAINER = '/container-probe'
DOBJECT = '/dataobject-probe'

OPWAIT = 2

DEFAULT_PORT = 443

def errmsg_from_excp(e):
    if getattr(e, 'args', False):
        retstr = ''
        if isinstance(e.args, basestring):
            return e.args
        elif isinstance(e.args, list) or isinstance(e.args, tuple) \
                or isinstance(e.args, dict):
            for s in e.args:
                if isinstance(s, str):
                    retstr += s + ' '
                if isinstance(s, tuple):
                    retstr += ' '.join(s)
                if isinstance(s, Exception):
                    retstr = str(s)
            return retstr
        else:
            for s in e.args:
                retstr += str(s) + ' '
            return retstr
    else:
        return str(e)


def server_ok(serverarg, capath, timeout):
    server_ctx = Context(TLSv1_METHOD)
    server_ctx.load_verify_locations(None, capath)

    def verify_cb(conn, cert, errnum, depth, ok):
        return ok
    server_ctx.set_verify(VERIFY_PEER|VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)

    serverarg = re.split("/*", serverarg)[1]
    if ':' in serverarg:
        serverarg = serverarg.split(':')
        server = serverarg[0]
        port = int(serverarg[1])
    else:
        server = serverarg
        port = DEFAULT_PORT

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, port))

        server_conn = Connection(server_ctx, sock)
        server_conn.set_connect_state()

        try:
            def handler(signum, frame):
                raise socket.error([('Timeout', 'after', str(timeout) + 's')])

            signal.signal(signal.SIGALRM, handler)
            signal.alarm(timeout)
            server_conn.do_handshake()
            signal.alarm(0)
        except socket.timeout as e:
            nagios_out('Critical', 'Connection error %s - %s' % (server + ':' + str(port), errmsg_from_excp(e)), 2)

        server_conn.shutdown()
        server_conn.close()

    except(SSLError, socket.error) as e:
        if 'sslv3 alert handshake failure' in errmsg_from_excp(e):
            pass
        else:
            nagios_out('Critical', 'Connection error %s - %s' % (server + ':' + str(port), errmsg_from_excp(e)), 2)

    return True


def nagios_out(status, msg, retcode):
    sys.stdout.write(status+": "+msg+"\n")
    sys.exit(retcode)


def get_token(server, userca, capath, timeout, cdmiver):
    try:
        # initiate unauthorized response (HTTP 401) with keystone URL
        headers, token = {}, None
        headers.update(cdmiver)
        headers.update({'Accept': '*/*'})
        response = requests.get(server, headers=headers, cert=userca, verify=False, timeout=timeout)
        if response.status_code == 400:
            response = requests.get(server, headers={}, cert=userca, verify=False)
    except requests.exceptions.ConnectionError as e:
        nagios_out('Critical', 'Connection error %s - %s' % (server, errmsg_from_excp(e)), 2)

    try:
        # extract public keystone URL from response
        keystone_server = re.search("Keystone.*=[\s'\"]*([\w:/\-_\.]*)[\s*\'\"]*", response.headers['www-authenticate']).group(1)
        if ':5000' not in keystone_server:
            raise AttributeError
    except(KeyError, IndexError, AttributeError):
        raise Exception('Could not fetch keystone server from response: Key not found %s' % errmsg_from_excp(e))

    if server_ok(keystone_server, capath, timeout):
        try:
            # fetch unscoped token
            token_suffix = ''
            if keystone_server.endswith("v2.0"):
                token_suffix = token_suffix+'/tokens'
            else:
                token_suffix = token_suffix+'/v2.0/tokens'

            headers, payload, token = {}, {}, None
            headers.update(cdmiver)
            headers.update({'Accept': '*/*'})

            headers = {'content-type': 'application/json', 'accept': 'application/json'}
            payload = {'auth': {'voms': True}}
            response = requests.post(keystone_server+token_suffix, headers=headers,
                                    data=json.dumps(payload), cert=userca, verify=False, timeout=timeout)
            response.raise_for_status()
            token = response.json()['access']['token']['id']
        except(KeyError, IndexError) as e:
            raise Exception('Could not fetch unscoped keystone token from response: Key not found %s' % errmsg_from_excp(e))
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            nagios_out('Critical', 'Connection error %s - %s' % (keystone_server+token_suffix, errmsg_from_excp(e)), 2)

        try:
            # use unscoped token to get a list of allowed tenants mapped to
            # ops VO from VOMS proxy cert
            tenant_suffix= ''
            if keystone_server.endswith("v2.0"):
                tenant_suffix = tenant_suffix+'/tenants'
            else:
                tenant_suffix = tenant_suffix+'/v2.0/tenants'
            headers = {'content-type': 'application/json', 'accept': 'application/json'}
            headers.update({'x-auth-token': token})
            response = requests.get(keystone_server+tenant_suffix, headers=headers,
                                    data=None, cert=userca, verify=False, timeout=timeout)
            response.raise_for_status()
            tenants = response.json()['tenants']
            tenant = ''
            for t in tenants:
                if 'ops' in t['name']:
                    tenant = t['name']
                    break
            else:
                # if there is no "ops" tenant, use the first one
                tenant = tenants[0]['name']
        except(KeyError, IndexError) as e:
            raise Exception('could not fetch allowed tenants from response: Key not found %s' % errmsg_from_excp(e))
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            nagios_out('Critical', 'connection error %s - %s' % (keystone_server+tenant_suffix, errmsg_from_excp(e)), 2)

        try:
            # get scoped token for allowed tenant
            headers = {'content-type': 'application/json', 'accept': 'application/json'}
            payload = {'auth': {'voms': True, 'tenantName': tenant}}
            response = requests.post(keystone_server+token_suffix, headers=headers,
                                    data=json.dumps(payload), cert=userca, verify=False, timeout=timeout)
            response.raise_for_status()
            token = response.json()['access']['token']['id']
        except(KeyError, IndexError) as e:
            raise Exception('Critical', 'could not fetch scoped keystone token for %s from response: Key not found %s' % (tenant, errmsg_from_excp(e)))
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            nagios_out('Critical', 'connection error %s - %s' % (keystone_server+token_suffix, errmsg_from_excp(e)), 2)

        return token


def create_container(argholder, ks_token, cdmiver, container_name):
    # create container
    headers, payload= {}, {}
    headers.update(cdmiver)
    headers.update({'accept': CDMI_CONTAINER,
                    'content-type': CDMI_CONTAINER})
    headers.update({'x-auth-token': ks_token})
    response = requests.put(argholder.endpoint + container_name + '/',
                            headers=headers, cert=argholder.cert, verify=False)
    response.raise_for_status()


def delete_container(argholder, ks_token, cdmiver, container_name):
    # remove container
    headers, payload= {}, {}
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
    headers, payload= {}, {}
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
    headers, payload= {}, {}
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
            sys.stderr.write('Clean up error: %s\n' % errmsg_from_excp(e))
    try:
        delete_container(argholder, ks_token, cdmiver, container_name)
    except requests.exceptions.HTTPError as e:
        sys.stderr.write('Clean up error: %s\n' % errmsg_from_excp(e))


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
        nagios_out('Unknown', 'command-line arguments not specified, '+msg_error_args, 3)
    else:
        if not argholder.endpoint.startswith("http") \
                or not os.path.isfile(argholder.cert) \
                or not type(argholder.timeout) == int \
                or not os.path.isdir(argholder.capath):
            nagios_out('Unknown', 'command-line arguments are not correct', 3)

    if server_ok(argholder.endpoint, argholder.capath, argholder.timeout):
        ver = None
        for v, cdmiver in enumerate(HEADER_CDMI_VERSIONS):
            # fetch scoped token for ops VO
            try:
                ks_token = get_token(argholder.endpoint,
                                     argholder.cert,
                                     argholder.capath,
                                     argholder.timeout,
                                     cdmiver)
            except Exception as e:
                if v == len(HEADER_CDMI_VERSIONS) - 1:
                    nagios_out('Critical', e.message, 2)

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
            nagios_out('Critical', 'test - create_container failed %s' % errmsg_from_excp(e), 2)

        try:
            create_dataobject(argholder, ks_token, ver, container_name,
                              obj_name, randdata)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name)
            nagios_out('Critical', 'test - create_dataobject failed %s' % errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            data = get_dataobject(argholder, ks_token, ver, container_name,
                                  obj_name)
            if data != randdata:
                raise requests.exceptions.HTTPError('data integrity violated')
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            nagios_out('Critical', 'test - get_dataobject failed %s' % errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        newranddata = ''.join(random.sample('abcdefghij1234567890', 20))

        try:
            create_dataobject(argholder, ks_token, ver, container_name,
                              obj_name, newranddata)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            nagios_out('Critical', 'test - update_dataobject failed %s' % errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            data = get_dataobject(argholder, ks_token, ver, container_name,
                                  obj_name)
            if data != newranddata:
                raise requests.exceptions.HTTPError('data integrity violated')
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            nagios_out('Critical', 'test - get_dataobject failed %s' % errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            delete_dataobject(argholder, ks_token, ver, container_name,
                              obj_name)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            nagios_out('Critical', 'test - delete_dataobject failed %s' % errmsg_from_excp(e), 2)
        time.sleep(OPWAIT)

        try:
            delete_container(argholder, ks_token, ver, container_name)
        except requests.exceptions.HTTPError as e:
            clean_up(argholder, ks_token, ver, container_name, obj_name)
            nagios_out('Critical', 'test - delete_container failed %s' % errmsg_from_excp(e), 2)

        nagios_out('OK', 'container and dataobject creating, fetching and removing tests were successful', 0)

main()
