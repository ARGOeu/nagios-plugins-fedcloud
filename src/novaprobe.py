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
import json
import os
import time
import urlparse

import requests

from nagios_plugins_fedcloud import helpers

# time to sleep between status checks
STATUS_SLEEP_TIME = 2
SERVER_NAME = "cloudmonprobe-servertest"


def get_image_id(glance_url, appdb_id, session):
    next_url = "v2/images"
    try:
        # TODO: query for the exact image directly once that info is available in glance
        # that should remove the need for the loop
        while next_url:
            images_url = urlparse.urljoin(glance_url, next_url)
            response = session.get(images_url)
            response.raise_for_status()
            for img in response.json()["images"]:
                if img.get("ad:appid", "") == appdb_id:
                    return img["id"]
                # TODO: this is to be deprecated as sites move to newer cloudkeeper
                attrs = json.loads(img.get("APPLIANCE_ATTRIBUTES", "{}"))
                if attrs.get("ad:appid", "") == appdb_id:
                    return img["id"]
            next_url = response.json().get("next", "")
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
    ) as e:
        helpers.nagios_out(
            "Critical", "Could not fetch image ID: %s" % helpers.errmsg_from_excp(e), 2
        )
    except (AssertionError, IndexError, AttributeError) as e:
        helpers.nagios_out("Critical", "Could not fetch image ID: %s" % str(e), 2)
    helpers.nagios_out(
        "Critical", "Could not find image ID for AppDB image %s" % appdb_id, 2
    )


def get_smaller_flavor_id(nova_url, session):
    flavor_url = nova_url + "/flavors/detail"
    # flavors with at least 8GB of disk, sorted by number of cpus
    query = {"minDisk": "8", "sort_dir": "asc", "sort_key": "vcpus"}
    try:

        response = session.get(flavor_url, params=query)
        response.raise_for_status()
        flavors = response.json()["flavors"]
        # minimum number of CPUs from first result (they are sorted)
        min_cpu = flavors[0]["vcpus"]
        # take the first one after ordering by RAM
        return sorted(
            filter(lambda x: x["vcpus"] == min_cpu, flavors), key=lambda x: x["ram"]
        ).pop(0)["id"]
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
    ) as e:
        helpers.nagios_out(
            "Critical", "Could not fetch flavor ID: %s" % helpers.errmsg_from_excp(e), 2
        )
    except (AssertionError, IndexError, AttributeError) as e:
        helpers.nagios_out("Critical", "Could not fetch flavor ID: %s" % str(e), 2)


def wait_for_delete(nova_url, server_id, vm_timeout, session):
    server_deleted = False
    i = 0
    helpers.debug("Check server %s status every %ds:" % (server_id, STATUS_SLEEP_TIME))
    while i < vm_timeout / STATUS_SLEEP_TIME:
        # server status
        try:
            response = session.get(nova_url + "/servers")
            servfound = False
            for s in response.json()["servers"]:
                if server_id == s["id"]:
                    servfound = True
                    response = session.get(nova_url + "/servers/%s" % server_id)
                    response.raise_for_status()
                    status = response.json()["server"]["status"]
                    helpers.debug(status, False)
                    if status.startswith("DELETED"):
                        server_deleted = True
                        break
            if not servfound:
                server_deleted = True
                helpers.debug("DELETED (Not found)", False)
            if server_deleted:
                break
            time.sleep(STATUS_SLEEP_TIME)
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            AssertionError,
            IndexError,
            AttributeError,
        ) as e:
            server_deleted = True
            helpers.debug(
                "Could not fetch server:%s status: %s - server is DELETED"
                % (server_id, helpers.errmsg_from_excp(e))
            )
            break
        i += 1
    return server_deleted


def delete_server(nova_url, server_id, session):
    try:
        helpers.debug("Trying to delete server=%s" % server_id)
        response = session.delete(nova_url + "/servers/%s" % (server_id))
        response.raise_for_status()
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
        AssertionError,
        IndexError,
        AttributeError,
    ) as e:
        helpers.debug("Error from server while deleting server: %s" % response.text)
        helpers.nagios_out(
            "Critical",
            "could not execute DELETE server=%s: %s"
            % (server_id, helpers.errmsg_from_excp(e)),
            2,
        )


def clean_up(nova_url, vm_timeout, session):
    try:
        response = session.get(nova_url + "/servers")
        for s in response.json()["servers"]:
            if s["name"] == SERVER_NAME:
                helpers.debug("Found old server %s, waiting for it" % s["id"])
                if not wait_for_delete(nova_url, s["id"], vm_timeout, session):
                    helpers.debug("Old server is still around after timeout, deleting")
                    delete_server(nova_url, s["id"], session)
                    helpers.nagios_out(
                        "Warning",
                        "Previous monitoring instance deleted, probe won't go on!",
                        1,
                    )
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
        AssertionError,
        IndexError,
        AttributeError,
    ) as e:
        helpers.debug(
            "Something went wrong while cleaning up, should be still ok: %s"
            % helpers.errmsg_from_excp(e)
        )


def wait_for_active(nova_url, server_id, vm_timeout, session):
    i, tss = 0, 3
    helpers.debug("Check server status every %ds: " % (STATUS_SLEEP_TIME))
    while i < vm_timeout / STATUS_SLEEP_TIME:
        # server status
        try:
            response = session.get(nova_url + "/servers/%s" % (server_id))
            response.raise_for_status()
            status = response.json()["server"]["status"]
            helpers.debug(status, False)
            if "ACTIVE" in status:
                return True
            if "ERROR" in status:
                helpers.debug(
                    "Error from nova: %s" % response.json()["server"].get("fault", "")
                )
                return False
            time.sleep(STATUS_SLEEP_TIME)
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            AssertionError,
            IndexError,
            AttributeError,
        ) as e:
            if i < tss:
                helpers.debug(
                    "Try to fetch server:%s status one more time. Error was %s\n"
                    % (server_id, helpers.errmsg_from_excp(e))
                )
                helpers.debug("Check server status every %ds: " % (STATUS_SLEEP_TIME))
            else:
                helpers.nagios_out(
                    "Critical",
                    "could not fetch server:%s status: %s"
                    % (server_id, helpers.errmsg_from_excp(e)),
                    2,
                )
        i += 1
    else:
        helpers.nagios_out(
            "Critical",
            "could not create server:%s, timeout:%d exceeded" % (server_id, vm_timeout),
            2,
        )
        return False


def create_server(nova_url, image, flavor_id, network_id, session):
    try:
        payload = {
            "server": {"name": SERVER_NAME, "imageRef": image, "flavorRef": flavor_id}
        }
        if network_id:
            payload["server"]["networks"] = [{"uuid": network_id}]
        response = session.post(nova_url + "/servers", data=json.dumps(payload))
        response.raise_for_status()
        server_id = response.json()["server"]["id"]
        helpers.debug("Creating server:%s name:%s" % (server_id, SERVER_NAME))
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
        AssertionError,
        IndexError,
        AttributeError,
    ) as e:
        helpers.debug("Error from server while creating server: %s" % response.text)
        helpers.nagios_out(
            "Critical",
            "Could not launch server from image UUID:%s: %s"
            % (image, helpers.errmsg_from_excp(e)),
            2,
        )
    return server_id


def main():
    class ArgHolder(object):
        pass

    argholder = ArgHolder()

    argnotspec = []
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", dest="endpoint", nargs="?")
    parser.add_argument("-v", dest="verb", action="store_true")
    parser.add_argument("--flavor", dest="flavor", nargs="?")
    parser.add_argument("--image", dest="image", nargs="?")
    parser.add_argument("--cert", dest="cert", nargs="?")
    parser.add_argument("--access-token", dest="access_token", nargs="?")
    parser.add_argument("--access-token-2", dest="access_token_2", nargs="?")
    parser.add_argument("-t", dest="timeout", type=int, nargs="?", default=120)
    parser.add_argument(
        "--vm-timeout", dest="vm_timeout", type=int, nargs="?", default=300
    )
    parser.add_argument("--appdb-image", dest="appdb_img", nargs="?")
    parser.add_argument(
        "--identity-provider", dest="identity_provider", default="egi.eu", nargs="?"
    )
    parser.add_argument(
        "--region", dest="region", default=None, nargs="?"
    )

    parser.parse_args(namespace=argholder)
    helpers.verbose = argholder.verb

    for arg in ["endpoint", "timeout"]:
        if eval("argholder." + arg) is None:
            argnotspec.append(arg)

    if argholder.cert is None and argholder.access_token is None:
        helpers.nagios_out(
            "Unknown", "cert or access-token command-line arguments not specified", 3
        )

    if argholder.image is None and argholder.appdb_img is None:
        helpers.nagios_out(
            "Unknown", "image or appdb-image command-line arguments not specified", 3
        )

    if len(argnotspec) > 0:
        msg_error_args = ""
        for arg in argnotspec:
            msg_error_args += "%s " % (arg)
        helpers.nagios_out(
            "Unknown", "command-line arguments not specified, " + msg_error_args, 3
        )
    else:
        if not argholder.endpoint.startswith("http"):
            helpers.nagios_out("Unknown", "command-line arguments are not correct", 3)
        if argholder.cert and not os.path.isfile(argholder.cert):
            helpers.nagios_out("Unknown", "cert file does not exist", 3)
        if argholder.access_token and not os.path.isfile(argholder.access_token):
            helpers.nagios_out("Unknown", "access-token file does not exist", 3)

    ks_token = None
    access_token = None
    access_token_2 = None
    if argholder.access_token:
        access_file = open(argholder.access_token, "r")
        access_token = access_file.read().rstrip("\n")
        access_file.close()

    if argholder.access_token_2:
        access_file = open(argholder.access_token_2, "r")
        access_token_2 = access_file.read().rstrip("\n")
        access_file.close()

    region = argholder.region

    for auth_class in [helpers.OIDCAuth, helpers.X509V3Auth, helpers.X509V2Auth]:
        # this is meant to support several issues while Check-in is transitioning from
        # MitreID to Keycloack
        for token in [argholder.access_token, argholder.access_token_2]:
            try:
                auth = auth_class(
                    argholder.endpoint,
                    argholder.timeout,
                    access_token=token,
                    identity_provider=argholder.identity_provider,
                    userca=argholder.cert,
                )
                ks_token = auth.authenticate()
                tenant_id, nova_url, glance_url, neutron_url = auth.get_info(region)
                helpers.debug("Authenticated with %s" % auth_class.name)
                break
            except helpers.AuthenticationException:
                # just go ahead
                helpers.debug("Authentication with %s failed" % auth_class.name)
    else:
        helpers.nagios_out("Critical", "Unable to authenticate against Keystone", 2)

    helpers.debug("Endpoint: %s" % argholder.endpoint)
    if region:
        helpers.debug("Region: %s" % region)
    helpers.debug("Auth token (cut to 64 chars): %.64s" % ks_token)
    helpers.debug("Project OPS, ID: %s" % tenant_id)
    helpers.debug("Nova: %s" % nova_url)
    helpers.debug("Glance: %s" % glance_url)
    helpers.debug("Neutron: %s" % neutron_url)

    # get a common session for not repeating the auth header code
    session = requests.Session()
    session.headers.update({"x-auth-token": ks_token})
    session.headers.update(
        {"content-type": "application/json", "accept": "application/json"}
    )
    session.timeout = argholder.timeout
    session.verify = True

    if not argholder.image:
        image = get_image_id(glance_url, argholder.appdb_img, session)
    else:
        image = argholder.image

    helpers.debug("Image: %s" % image)

    if not argholder.flavor:
        flavor_id = get_smaller_flavor_id(nova_url, session)
    else:
        # fetch flavor_id for given flavor (resource)
        try:
            response = session.get(nova_url + "/flavors")
            response.raise_for_status()
            flavors = response.json()["flavors"]
            flavor_id = None
            for f in flavors:
                if f["name"] == argholder.flavor:
                    flavor_id = f["id"]
            assert flavor_id is not None
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
        ) as e:
            helpers.nagios_out(
                "Critical",
                "could not fetch flavor ID, endpoint does not correctly exposes "
                "available flavors: %s" % helpers.errmsg_from_excp(e),
                2,
            )
        except (AssertionError, IndexError, AttributeError) as e:
            helpers.nagios_out(
                "Critical",
                "could not fetch flavor ID, endpoint does not correctly exposes "
                "available flavors: %s" % str(e),
                2,
            )

    helpers.debug("Flavor ID: %s" % flavor_id)

    network_id = None
    if neutron_url:
        try:
            response = session.get(neutron_url + "/v2.0/networks")
            response.raise_for_status()
            for network in response.json()["networks"]:
                # assume first available active network owned by the tenant is ok
                if network["status"] == "ACTIVE" and network["tenant_id"] == tenant_id:
                    network_id = network["id"]
                    helpers.debug("Network id: %s" % network_id)
                    break
            else:
                helpers.debug(
                    "No tenant-owned network found, hoping VM creation will "
                    "still work..."
                )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            AssertionError,
            IndexError,
            AttributeError,
        ) as e:
            helpers.nagios_out(
                "Critical",
                "Could not get network id: %s" % helpers.errmsg_from_excp(e),
                2,
            )

    else:
        helpers.debug("Skipping network discovery as there is no neutron endpoint")

    # remove previous servers if found
    clean_up(nova_url, argholder.vm_timeout, session)

    # create server
    st = time.time()
    server_id = create_server(nova_url, image, flavor_id, network_id, session)
    server_built = wait_for_active(nova_url, server_id, argholder.vm_timeout, session)
    server_createt = round(time.time() - st, 2)

    if server_built:
        helpers.debug("\nServer created in %.2f seconds" % (server_createt))

    # server delete
    st = time.time()
    delete_server(nova_url, server_id, session)
    server_deleted = wait_for_delete(nova_url, server_id, argholder.vm_timeout, session)
    server_deletet = round(time.time() - st, 2)
    helpers.debug("\nServer=%s deleted in %.2f seconds" % (server_id, server_deletet))

    if server_built and server_deleted:
        helpers.nagios_out(
            "OK",
            "Compute instance=%s created(%.2fs) and destroyed(%.2fs)"
            % (server_id, server_createt, server_deletet),
            0,
        )
    elif server_built:
        # Built but not deleted
        helpers.nagios_out(
            "Critical",
            "Compute instance=%s created (%.2fs) but not destroyed(%.2fs)"
            % (server_id, server_createt, server_deletet),
            2,
        )
    else:
        # not built but deleted
        helpers.nagios_out(
            "Critical",
            "Compute instance=%s created with error(%.2fs) and destroyed(%.2fs)"
            % (server_id, server_createt, server_deletet),
            2,
        )


main()
