#!/usr/bin/env python

# Copyright (C) 2021 EGI Foundation
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
from datetime import datetime

import requests
from six.moves.urllib.parse import urlparse, urlunparse

from nagios_plugins_fedcloud import helpers


def get_endpoint_from_appdb(endpoint, appdb_endpoint):
    # Get from AppDB the endpoint
    try:
        helpers.debug("Querying AppDB for endpoint %s" % endpoint)
        url = "/".join([appdb_endpoint, "rest/cloud/computing/endpoints"])
        params = {"filter": "endpointURL::eq:\"%s\"" % endpoint}
        r = requests.get(url,
                         params=params,
                         headers={"accept": "application/json"})
        r.raise_for_status()
        return r.json()["data"][0]["id"]
    except requests.exceptions.RequestException as e:
        msg = "Could not get info from AppDB: %s" % e
        helpers.nagios_out("Unknown", msg, 3)
    except (IndexError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--endpoint", dest="endpoint", required=True)
    parser.add_argument("-v", dest="verb", action="store_true")
    parser.add_argument("-t", dest="timeout", type=int, default=120)
    parser.add_argument("--appdb-endpoint",
                        default="https://is.appdb.egi.eu")
    parser.add_argument("--warning-treshold", type=int, default=1)
    parser.add_argument("--critical-treshold", type=int, default=5)
    opts = parser.parse_args()

    if opts.verb:
        helpers.verbose = True

    endpoint_id = get_endpoint_from_appdb(opts.endpoint, opts.appdb_endpoint)
    if not endpoint_id:
        # ARGO adds the port even if it's not originally in GOC, so try to
        # find the endpoint without it if it's HTTPS/443
        parsed = urlparse(opts.endpoint)
        if parsed[0] == "https" and parsed[1].endswith(":443"):
            helpers.debug("Retry query with no port in URL")
            new_endpoint = urlunparse((parsed[0],
                                       parsed[1][:-4],
                                       parsed[2],
                                       parsed[3],
                                       parsed[4],
                                       parsed[5]))
            endpoint_id = get_endpoint_from_appdb(new_endpoint,
                                                  opts.appdb_endpoint)

    if not endpoint_id:
        msg = "Could not get info from AppDB about endpoint %s" % opts.endpoint
        helpers.nagios_out("Critical", msg, 2)

    try:
        url = "/".join([opts.appdb_endpoint,
                        "rest/cloud/computing/endpoints/%s" % endpoint_id])
        r = requests.get(url,
                         params={"limit": "0", "skip": "0"},
                         headers={"accept": "application/json"})
        r.raise_for_status()
        vos = r.json()["data"]["shares"]
    except requests.exceptions.RequestException as e:
        msg = "Could not get info from AppDB: %s" % e
        helpers.nagios_out("Unknown", msg, 3)
    except (IndexError, ValueError):
        msg = "Could not get info from AppDB about endpoint %s" % opts.endpoint
        helpers.nagios_out("Critical", msg, 2)

    # Now check how old the information is
    # TODO: check if all the expected VOs are present
    today = datetime.today()
    for vo in vos:
        # entityCreationTime has the date where the info was produced
        # should look like "2020-12-14T10:50:56.773201"
        # will produce a Warning if the info is older than 1 day
        # or critical if older than 5 days
        updated = datetime.strptime(vo["entityCreationTime"][:16],
                                    "%Y-%m-%dT%H:%M")
        helpers.debug("VO %(VO)s updated by %(entityCreationTime)s" % vo)
        diff_days = ((today - updated).total_seconds()) / (60 * 60 * 24.)
        if diff_days > opts.critical_treshold:
            msg = ("VO %s info is older than %s days"
                   % (vo["VO"], opts.critical_treshold))
            helpers.nagios_out("Critical", msg, 2)
        elif diff_days > opts.warning_treshold:
            msg = ("VO %s info is older than %s days"
                   % (vo["VO"], opts.warning_treshold))
            helpers.nagios_out("Warning", msg, 1)

    helpers.nagios_out(
        "OK",
        "Endpoint publishing up to date information for VOs",
        0
    )


if __name__ == "__main__":
    main()
