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

import argparse
import os
import uuid

import requests
from nagios_plugins_fedcloud import helpers


class Swift:
    def __init__(self, swift_endpoint, token, session):
        if swift_endpoint[-1] == '/':
            swift_endpoint = swift_endpoint[:-1]
        self.swift_endpoint = swift_endpoint
        self.token = token
        self.session = session

    def put_container(self, container_id):
        url = self.swift_endpoint + '/' + container_id
        try:
            response = self.session.put(url)
            response.raise_for_status()

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError
        ) as e:
            helpers.debug(
                "Error while creating container: %s" %
                helpers.errmsg_from_excp(e)
            )
            helpers.nagios_out(
                "Critical",
                "Could not create new OpenStack Swift Container: %s: %s" % (
                    container_id, helpers.errmsg_from_excp(e)
                ),
                2
            )

    def put_object(self, container_id, object_id, data):
        url = self.swift_endpoint + '/' + container_id + '/' + object_id
        try:
            response = self.session.put(url, data=data)
            response.raise_for_status()

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError
        ) as e:
            helpers.debug(
                "Error while creating object %s in container %s: %s" % (
                    object_id, container_id, helpers.errmsg_from_excp(e)
                )
            )
            helpers.nagios_out(
                "Critical",
                "Could not create a new object file: %s: %s" % (
                    object_id, helpers.errmsg_from_excp(e)
                ),
                2
            )

    def get_object(self, container_id, object_id):
        url = self.swift_endpoint + '/' + container_id + '/' + object_id
        try:
            response = self.session.get(url)
            response.raise_for_status()
            data = response.content

            assert data

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            AssertionError
        ) as e:
            helpers.debug(
                "Error while fetching object %s file: %s" % (
                    object_id, helpers.errmsg_from_excp(e)
                )
            )
            helpers.nagios_out(
                "Critical",
                "Could not fetch object: %s: %s" % (
                    object_id, helpers.errmsg_from_excp(e)
                ),
                2
            )

    def delete_object(self, container_id, object_id):
        url = self.swift_endpoint + '/' + container_id + '/' + object_id
        try:
            response = self.session.delete(url)
            response.raise_for_status()

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError
        ) as e:
            helpers.debug(
                "Error while deleting object: %s: %s" % (
                    object_id, helpers.errmsg_from_excp(e)
                )
            )
            helpers.nagios_out(
                "Critical",
                "Could not delete object: %s: %s" % (
                    object_id, helpers.errmsg_from_excp(e)
                ),
                2
            )

    def delete_container(self, container_id):
        url = self.swift_endpoint + '/' + container_id
        try:
            response = self.session.delete(url)
            response.raise_for_status()
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError
        ) as e:
            helpers.debug(
                "Error while deleting container: %s: %s" % (
                    container_id, helpers.errmsg_from_excp(e)
                )
            )
            helpers.nagios_out(
                "Critical",
                "Could not delete the OpenStack Swift Container %s: %s" % (
                    container_id, helpers.msg_error_args(e)
                ),
                2
            )


def main():
    argnotspec = []
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--endpoint", dest="endpoint", type=str,
        help="The Keystone public endpoint"
    )
    parser.add_argument(
        "--cert", dest="cert", type=str, help="The X.509 proxy certificate"
    )
    parser.add_argument(
        "--access-token", dest="access_token", type=str, help="Access token"
    )
    parser.add_argument(
        "-t", "--timeout", dest="timeout", type=int, default=120,
        help="The max timeout (in sec) before exiting. Default is '120'."
    )
    parser.add_argument(
        "--identity-provider", dest="identity_provider", default="egi.eu",
        help="Identity provider. Default is 'egi.eu'."
    )
    parser.add_argument(
        "-v", "--verbose", dest="verbose", action="store_true", default=False
    )

    args = parser.parse_args()
    helpers.verbose = args.verbose

    if args.endpoint is None:
        argnotspec.append("endpoint")

    if args.cert is None and args.access_token is None:
        helpers.nagios_out(
            "Unknown",
            "cert or access-token command-line arguments not specified",
            3
        )

    if len(argnotspec) > 0:
        msg_error_args = ""
        for arg in argnotspec:
            msg_error_args += arg

        helpers.nagios_out(
            "Unknown",
            "command-line arguments not specified: " + msg_error_args,
            3
        )

    else:
        if not args.endpoint.startswith("http"):
            helpers.nagios_out(
                "Unknown", "command-line arguments are not correct", 3
            )

        if args.cert and not os.path.isfile(args.cert):
            helpers.nagios_out("Unknown", "cert file does not exist", 3)

        if args.access_token and not os.path.isfile(args.access_token):
            helpers.nagios_out("Unknown", "access-token file does not exist", 3)

    ks_token = None
    access_token = None
    if args.access_token:
        access_file = open(args.access_token, 'r')
        access_token = access_file.read().rstrip('\n')
        access_file.close()

    for auth_class in [
        helpers.OIDCAuth, helpers.X509V3Auth, helpers.X509V2Auth
    ]:
        try:
            auth = auth_class(
                args.endpoint,
                args.timeout,
                access_token=access_token,
                identity_provider=args.identity_provider,
                userca=args.cert
            )
            ks_token = auth.authenticate()
            tenant_id, swift_endpoint = auth.get_swift_endpoint()
            helpers.debug("Authenticated with %s" % auth_class.name)
            break

        except helpers.AuthenticationException:
            helpers.debug("Authentication with %s failed" % auth_class.name)

    else:
        helpers.nagios_out(
            "Critical", "Unable to authenticate against Keystone", 2
        )

    helpers.debug("Swift public endpoint: %s" % swift_endpoint)
    helpers.debug("Auth token (cut to 64 chars): %.64s" % ks_token)
    helpers.debug("Project OPS, ID: %s" % tenant_id)

    # Creating a new Container
    container_id = "container-" + str(uuid.uuid4())
    object_id = "file-" + str(uuid.uuid4())
    data = "This is just an ASCII file\n"

    helpers.debug(
        "Establish a connection with the OpenStack Swift Object Storage"
    )
    session = requests.Session()
    session.headers.update({"x-auth-token": ks_token})
    session.headers.update(
        {"content-type": "application/json", "accept": "application/json"}
    )
    session.timeout = args.timeout
    session.verify = True

    _swift = Swift(
        swift_endpoint=swift_endpoint, token=ks_token, session=session
    )

    helpers.debug("Create a new OpenStack Swift Container: %s" % container_id)
    _swift.put_container(container_id)

    helpers.debug("Create a new object file: %s" % object_id)
    _swift.put_object(container_id, object_id, data)

    helpers.debug("Fetch the object file")
    _swift.get_object(container_id, object_id)

    helpers.debug("Delete the object file: %s" % object_id)
    _swift.delete_object(container_id, object_id)

    helpers.debug("Delete the OpenStack Swift Container %s" % container_id)
    _swift.delete_container(container_id)

    helpers.debug("Close connection with the OpenStack Swift Object Storage")
    session.close()

    helpers.nagios_out(
        "OK",
        "OpenStack Swift Container %s created and destroyed, "
        "object %s created and destroyed" % (container_id, object_id),
        0
    )


if __name__ == '__main__':
    main()
