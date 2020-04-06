import json
import os
import sys

import requests

from urlparse import urlparse


strerr = ""
num_excp_expand = 0
extra_out = []
verbose = False


class AuthenticationException(Exception):
    pass


def nagios_out(status, msg, retcode):
    sys.stdout.write(status + ": " + msg + "\n")
    global extra_out
    global verbose
    if extra_out and verbose:
        sys.stdout.write("\n".join(extra_out))
    sys.exit(retcode)


def debug(msg, newline=True):
    global verbose
    if not verbose:
        return
    global extra_out
    if newline:
        extra_out.append(msg)
    else:
        if not extra_out:
            extra_out.append("")
        extra_out[-1] = " ".join((extra_out[-1], msg))


class BaseAuth(object):
    def __init__(self, host, timeout, **kwargs):
        self.parsed_url = urlparse(host)
        self.timeout = timeout
        if self.parsed_url.scheme != "https":
            raise AuthenticationException(
                "Connection error %s - Probe expects HTTPS endpoint"
                % (self.parsed_url.scheme + "://" + self.parsed_url.netloc)
            )
        s = self.parsed_url.path.rstrip("/")
        if s.endswith("v2.0") or s.endswith("v3"):
            s = os.path.dirname(s)
        self.suffix = s.rstrip("/")

    def get_unscoped_token(self):
        raise NotImplementedError

    def get_ops_tenant(self):
        raise NotImplementedError

    def get_scoped_token(self):
        raise NotImplementedError

    def authenticate(self):
        unscoped_token = self.get_unscoped_token()
        tenant = self.get_ops_tenant(unscoped_token)
        return self.get_scoped_token(unscoped_token, tenant)

    def get_info(self):
        raise NotImplementedError

    def get_swift_endpoint(self):
        raise NotImplementedError


class BaseV3Auth(BaseAuth):
    def get_ops_tenant(self, unscoped_token):
        try:
            # use unscoped token to get a list of allowed projects mapped to
            # ops VO from atuh token
            project_suffix = self.suffix + "/v3/auth/projects"

            headers = {"content-type": "application/json", "accept": "application/json"}
            headers.update({"x-auth-token": unscoped_token})
            url = (
                self.parsed_url.scheme + "://" + self.parsed_url.netloc + project_suffix
            )
            response = requests.get(
                url, headers=headers, data=None, timeout=self.timeout, verify=True
            )
            response.raise_for_status()
            projects = response.json()["projects"]
            for p in projects:
                if "ops" in p["name"]:
                    return p
            else:
                # just take one
                return projects.pop()
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch allowed projects from response: Key not found %s"
                % errmsg_from_excp(e)
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise AuthenticationException(
                "Connection error %s - %s" % (url, errmsg_from_excp(e))
            )

    def get_scoped_token(self, unscoped_token, project):
        try:
            # get scoped token for allowed project
            token_suffix = self.suffix + "/v3/auth/tokens"
            headers = {"content-type": "application/json", "accept": "application/json"}
            payload = {
                "auth": {
                    "identity": {"methods": ["token"], "token": {"id": unscoped_token}},
                    "scope": {"project": {"id": project["id"]}},
                }
            }
            url = self.parsed_url.scheme + "://" + self.parsed_url.netloc + token_suffix
            self.token_response = requests.post(
                url,
                headers=headers,
                data=json.dumps(payload),
                verify=True,
                timeout=self.timeout,
            )
            self.token_response.raise_for_status()
            return self.token_response.headers["X-Subject-Token"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch scoped keystone token for %s from "
                "response: Key not found %s" % (project, errmsg_from_excp(e))
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise AuthenticationException(
                "Connection error %s - %s" % (url, errmsg_from_excp(e))
            )

    def get_info(self):
        try:
            tenant_id = self.token_response.json()["token"]["project"]["id"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch id for project: %s" % errmsg_from_excp(e)
            )
        try:
            service_catalog = self.token_response.json()["token"]["catalog"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch service catalogue %s" % errmsg_from_excp(e)
            )
        r = dict(compute=None, image=None, network=None)
        try:
            for e in service_catalog:
                if e["type"] in r:
                    for ep in e["endpoints"]:
                        if ep["interface"] == "public":
                            r[e["type"]] = ep["url"]
            assert r["compute"] and r["image"]
        except (KeyError, IndexError, AssertionError) as e:
            raise AuthenticationException(
                "Could not fetch service URL: %s" % errmsg_from_excp(e)
            )
        return tenant_id, r["compute"], r["image"], r["network"]

    def get_swift_endpoint(self):
        try:
            tenant_id = self.token_response.json()["token"]["project"]["id"]

        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch id for project: %s" % errmsg_from_excp(e)
            )

        try:
            service_catalog = self.token_response.json()["token"]["catalog"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch service catalogue: %s" % errmsg_from_excp(e)
            )

        try:
            for e in service_catalog:
                if e["type"] == "object-store":
                    for ep in e["endpoints"]:
                        if ep["interface"] == "public":
                            swift_endpoint = ep["url"]

            assert swift_endpoint

        except (KeyError, IndexError, AssertionError) as e:
            raise AuthenticationException(
                "Could not fetch swift URL: %s" % errmsg_from_excp(e)
            )

        return tenant_id, swift_endpoint


class OIDCAuth(BaseV3Auth):
    name = "OpenID Connect"

    def __init__(
        self, host, timeout, identity_provider="egi.eu", access_token="", **kwargs
    ):
        super(OIDCAuth, self).__init__(host, timeout, **kwargs)
        self.identity_provider = identity_provider
        self.access_token = access_token

    def get_unscoped_token(self):
        for p in ["openid", "oidc"]:
            try:
                debug("TEST %s" % p)
                return self._get_unscoped_token_with_protocol(p)
            except AuthenticationException as e:
                debug("OIDC Auth failed with protocol %s (%s)" % (p, e))
        raise AuthenticationException("Unable to authenticate")

    def _get_unscoped_token_with_protocol(self, protocol):
        try:
            auth_url = "/v3/OS-FEDERATION/identity_providers/%s/protocols/%s/auth" % (
                self.identity_provider,
                protocol,
            )
            oidc_suffix = self.suffix + auth_url

            headers = {}
            headers.update({"Authorization": "Bearer " + self.access_token})
            headers.update({"accept": "application/json"})
            response = requests.post(
                self.parsed_url.scheme + "://" + self.parsed_url.netloc + oidc_suffix,
                headers=headers,
                timeout=self.timeout,
                verify=True,
            )
            response.raise_for_status()
            return response.headers["X-Subject-Token"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch unscoped keystone token from response: %s"
                % errmsg_from_excp(e)
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise AuthenticationException(
                "Connection error %s - %s"
                % (self.parsed_url.netloc + oidc_suffix, errmsg_from_excp(e))
            )


class X509V3Auth(BaseV3Auth):
    name = "VOMS Keystone-V3"

    def __init__(self, host, timeout, identity_provider="egi.eu", userca="", **kwargs):
        super(X509V3Auth, self).__init__(host, timeout, **kwargs)
        self.identity_provider = identity_provider
        self.protocol = "mapped"
        self.userca = userca

    def get_unscoped_token(self):
        try:
            auth_url = "/v3/OS-FEDERATION/identity_providers/%s/protocols/%s/auth" % (
                self.identity_provider,
                self.protocol,
            )
            token_suffix = self.suffix + auth_url

            headers = {}
            headers.update({"accept": "application/json"})

            response = requests.post(
                self.parsed_url.scheme + "://" + self.parsed_url.netloc + token_suffix,
                headers=headers,
                cert=self.userca,
                verify=True,
                timeout=self.timeout,
            )

            response.raise_for_status()
            return response.headers["X-Subject-Token"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch unscoped keystone token from response: %s"
                % errmsg_from_excp(e)
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise AuthenticationException(
                "Connection error %s - %s"
                % (self.parsed_url.netloc + token_suffix, errmsg_from_excp(e))
            )


class X509V2Auth(BaseAuth):
    name = "Keystone-VOMS"

    def __init__(self, host, timeout, userca="", **kwargs):
        super(X509V2Auth, self).__init__(host, timeout, **kwargs)
        self.userca = userca

    def get_unscoped_token(self):
        try:
            # fetch unscoped token
            token_suffix = self.suffix + "/v2.0/tokens"

            headers, payload = {}, {}
            headers.update({"Accept": "*/*"})

            headers = {"content-type": "application/json", "accept": "application/json"}
            payload = {"auth": {"voms": True}}
            response = requests.post(
                self.parsed_url.scheme + "://" + self.parsed_url.netloc + token_suffix,
                headers=headers,
                data=json.dumps(payload),
                cert=self.userca,
                verify=True,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()["access"]["token"]["id"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch unscoped keystone token from response: %s"
                % errmsg_from_excp(e)
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise AuthenticationException(
                "Connection error %s - %s"
                % (self.parsed_url.netloc + token_suffix, errmsg_from_excp(e))
            )

    def get_ops_tenant(self, token):
        try:
            # use unscoped token to get a list of allowed tenants mapped to
            # ops VO from VOMS proxy cert
            tenant_suffix = self.suffix + "/v2.0/tenants"

            headers = {"content-type": "application/json", "accept": "application/json"}
            headers.update({"x-auth-token": token})
            url = (
                self.parsed_url.scheme + "://" + self.parsed_url.netloc + tenant_suffix
            )
            response = requests.get(
                url,
                headers=headers,
                data=None,
                cert=self.userca,
                verify=True,
                timeout=self.timeout,
            )
            response.raise_for_status()
            tenants = response.json()["tenants"]
            for t in tenants:
                if "ops" in t["name"]:
                    return t["name"]
            else:
                # just take one
                return tenants.pop()["name"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch allowed tenants from response: Key not found %s"
                % errmsg_from_excp(e)
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise AuthenticationException(
                "Connection error %s - %s" % (url, errmsg_from_excp(e))
            )

    def get_scoped_token(self, unscoped_token, tenant):
        try:
            token_suffix = self.suffix + "/v2.0/tokens"
            # get scoped token for allowed tenant
            headers = {"content-type": "application/json", "accept": "application/json"}
            payload = {"auth": {"voms": True, "tenantName": tenant}}
            url = self.parsed_url.scheme + "://" + self.parsed_url.netloc + token_suffix
            self.token_response = requests.post(
                url,
                headers=headers,
                data=json.dumps(payload),
                cert=self.userca,
                verify=True,
                timeout=self.timeout,
            )
            self.token_response.raise_for_status()
            return self.token_response.json()["access"]["token"]["id"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch scoped keystone token for %s from "
                "response: Key not found %s" % (tenant, errmsg_from_excp(e))
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise AuthenticationException(
                "Connection error %s - %s" % (url, errmsg_from_excp(e))
            )

    def get_info(self):
        try:
            tenant_id = self.token_response.json()["access"]["token"]["tenant"]["id"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch id for tenant: %s" % errmsg_from_excp(e)
            )
        try:
            service_catalog = self.token_response.json()["access"]["serviceCatalog"]
        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch service catalog: %s" % (errmsg_from_excp(e))
            )
        r = dict(compute=None, image=None, network=None)
        try:
            for e in service_catalog:
                if e["type"] in r:
                    r[e["type"]] = e["endpoints"][0]["publicURL"]
            assert r["compute"] and r["image"]
        except (KeyError, IndexError, AssertionError) as e:
            raise AuthenticationException(
                "Could not fetch service URL: %s" % (errmsg_from_excp(e))
            )

        return tenant_id, r["compute"], r["image"], r["network"]

    def get_swift_endpoint(self):
        try:
            tenant_id = \
                self.token_response.json()["access"]["token"]["tenant"]["id"]

        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch id for tenant: %s" % errmsg_from_excp(e)
            )

        try:
            service_catalog = \
                self.token_response.json()["access"]["serviceCatalog"]

        except (KeyError, IndexError) as e:
            raise AuthenticationException(
                "Could not fetch service catalog: %s" % errmsg_from_excp(e)
            )

        try:
            for e in service_catalog:
                if e["type"] == "object-store":
                    swift_endpoint = e["endpoints"][0]["publicURL"]

            assert swift_endpoint

        except (KeyError, IndexError, AssertionError) as e:
            raise AuthenticationException(
                "Could not fetch swift URL: %s" % errmsg_from_excp(e)
            )

        return tenant_id, swift_endpoint


def errmsg_from_excp(e, level=5):
    global strerr, num_excp_expand
    if isinstance(e, Exception) and getattr(e, "args", False):
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
            strerr += e + " "
