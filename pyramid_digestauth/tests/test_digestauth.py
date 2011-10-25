import unittest

import os
import time
import wsgiref.util

from pyramid.testing import DummyRequest

from pyramid_digestauth import DigestAuthenticationPolicy
from pyramid_digestauth.noncemanager import SignedNonceManager
from pyramid_digestauth.parseauthz import parse_authz_header
from pyramid_digestauth.utils import (calculate_digest_response,
                                      calculate_pwdhash,
                                      validate_digest_parameters,
                                      validate_digest_uri)


def make_request(**kwds):
    environ = {}
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return DummyRequest(environ=environ)


def get_response(app, request):
    output = []
    def start_response(status, headers, exc_info=None): # NOQA
        output.append(status + "\r\n")
        for name, value in headers:
            output.append("%s: %s\r\n" % (name, value))
        output.append("\r\n")
    for chunk in app(request.environ, start_response):
        output.append(chunk)
    return "".join(output)


def get_password(username):
    return username


def get_pwdhash(username, realm):
    return calculate_pwdhash(username, username, realm)


def get_challenge(policy, request):
    """Get a new digest-auth challenge from the policy."""
    for name, value in policy.forget(request):
        if name == "WWW-Authenticate":
            req = make_request(HTTP_AUTHORIZATION=value)
            return parse_authz_header(req)
    raise ValueError("policy didn't issue a challenge")


def build_response(params, request, username, password, **kwds):
    """Build a response to the digest-auth challenge."""
    params = params.copy()
    # remove qop from the challenge parameters.
    params.pop("qop", None)
    params.update(kwds)
    params.setdefault("username", username)
    params.setdefault("uri", wsgiref.util.request_uri(request.environ))
    # do qop=auth unless specified otherwise in kwds
    params.setdefault("qop", "auth")
    if not params["qop"]:
        del params["qop"]
    else:
        params.setdefault("cnonce", os.urandom(8).encode("hex"))
        params.setdefault("nc", "0000001")
    resp = calculate_digest_response(params, request, password=password)
    params["response"] = resp
    set_authz_header(request, params)
    return params


def set_authz_header(request, params):
    """Set Authorization header to match the given params."""
    authz = ",".join('%s="%s"' % v for v in params.iteritems())
    request.environ["HTTP_AUTHORIZATION"] = "Digest " + authz


class EasyNonceManager(object):
    """NonceManager that thinks everything is valid."""

    def generate_nonce(self, request):
        return "aaa"

    def is_valid_nonce(self, nonce, request):
        return True

    def get_next_nonce(self, nonce, request):
        return nonce + "a"

    def get_nonce_count(self, nonce):
        return None

    def set_nonce_count(self, nonce, nc):
        return None


class TestDigestAuthenticationPolicy(unittest.TestCase):
    """Testcases for the main DigestAuthenticationPolicy class."""

    def test_from_settings(self):
        def ref(class_name):
            return __name__ + ":" + class_name
        policy = DigestAuthenticationPolicy.from_settings(
                             realm="test",
                             nonce_manager=ref("EasyNonceManager"),
                             domain="http://example.com",
                             get_pwdhash=ref("get_pwdhash"),
                             get_password=ref("get_password"))
        self.assertEquals(policy.realm, "test")
        self.assertEquals(policy.domain, "http://example.com")
        self.failUnless(isinstance(policy.nonce_manager, EasyNonceManager))
        self.failUnless(policy.get_pwdhash is get_pwdhash)
        self.failUnless(policy.get_password is get_password)

    # Tests for the low-level credentials extraction

    def test_identify_with_no_authz(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request()
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_non_digest_authz(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request(HTTP_AUTHORIZATION="Basic lalalala")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        request = make_request(HTTP_AUTHORIZATION="BrowserID assertion=1234")
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_invalid_params(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request(HTTP_AUTHORIZATION="Digest realm=Sync")
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_mismatched_uri(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request(PATH_INFO="/path_one")
        params = get_challenge(policy, request)
        build_response(params, request, "tester", "testing")
        self.assertNotEquals(policy.unauthenticated_userid(request), None)
        request["PATH_INFO"] = "/path_two"
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_bad_noncecount(self):
        policy = DigestAuthenticationPolicy("test",
                                            get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/one")
        # Do an initial auth to get the nonce.
        params = get_challenge(policy, request)
        build_response(params, request, "tester", "testing", nc="01")
        self.assertNotEquals(policy.unauthenticated_userid(request), None)
        # Authing without increasing nc will fail.
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="01")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # Authing with a badly-formed nc will fail
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02XXX")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # Authing with a badly-formed nc will fail
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02XXX")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # Authing with increasing nc will succeed.
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02")
        self.assertNotEquals(policy.unauthenticated_userid(request), None)

    # Tests for various ways that authentication can go right or wrong

    def test_rfc2617_example(self):
        password = "Circle Of Life"
        params = {"username": "Mufasa",
                  "realm": "testrealm@host.com",
                  "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                  "uri": "/dir/index.html",
                  "qop": "auth",
                  "nc": "00000001",
                  "cnonce": "0a4f113b",
                  "opaque": "5ccc069c403ebaf9f0171e9517f40e41"}
        policy = DigestAuthenticationPolicy("testrealm@host.com",
                                            EasyNonceManager(),
                                            get_password=lambda u: password)
        # Calculate the response according to the RFC example parameters.
        request = make_request(REQUEST_METHOD="GET",
                               PATH_INFO="/dir/index.html")
        resp = calculate_digest_response(params, request, password=password)
        # Check that it's as expected from the RFC example section.
        self.assertEquals(resp, "6629fae49393a05397450978507c4ef1")
        # Check that we can auth using it.
        params["response"] = resp
        set_authz_header(request, params)
        self.assertEquals(policy.unauthenticated_userid(request), "Mufasa")
        self.assertEquals(policy.authenticated_userid(request), "Mufasa")

    def test_auth_good_post(self):
        policy = DigestAuthenticationPolicy("test",
                                            get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="POST", PATH_INFO="/do/stuff")
        params = get_challenge(policy, request)
        build_response(params, request, "tester", "testing")
        self.assertNotEquals(policy.authenticated_userid(request), None)

    def test_auth_good_get_with_vars(self):
        pwdhash = calculate_pwdhash("tester", "testing", "test")
        policy = DigestAuthenticationPolicy("test",
                                            get_pwdhash=lambda u, r: pwdhash)
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/hi?who=me")
        params = get_challenge(policy, request)
        build_response(params, request, "tester", "testing")
        self.assertNotEquals(policy.authenticated_userid(request), None)

    def test_auth_good_legacy_mode(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/legacy")
        params = get_challenge(policy, request)
        params = build_response(params, request, "tester", "testing", qop=None)
        self.failIf("qop" in params)
        self.assertNotEquals(policy._authenticate(request, params), None)

    def test_auth_good_authint_mode(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/authint",
                               HTTP_CONTENT_MD5="1B2M2Y8AsgTpgAmY7PhCfg==")
        params = get_challenge(policy, request)
        params = build_response(params, request, "tester", "testing",
                                qop="auth-int")
        self.assertNotEquals(policy._authenticate(request, params), None)

    def test_auth_with_no_identity(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request()
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_different_realm(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request)
        params["realm"] = "other-realm"
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_no_password_callbacks(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request()
        params = get_challenge(policy, request)
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_bad_digest_response(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request)
        params = build_response(params, request, "tester", "testing")
        authz = request.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(params["response"], "WRONG")
        request.environ["HTTP_AUTHORIZATION"] = authz
        params["response"] += "WRONG"
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_unknown_qop(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request)
        params = build_response(params, request, "tester", "testing")
        params["qop"] = "super-duper"
        self.assertRaises(ValueError, policy._authenticate, request, params)

    def test_auth_with_failed_password_lookup(self):
        policy = DigestAuthenticationPolicy("test", get_pwdhash=lambda u, r: None)
        request = make_request()
        params = get_challenge(policy, request)
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.unauthenticated_userid(request), "tester")
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_missing_nonce(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request)
        build_response(params, request, "tester", "testing")
        authz = request.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(" nonce", " notanonce")
        request.environ["HTTP_AUTHORIZATION"] = authz
        self.assertEquals(policy.unauthenticated_userid(request), None)
        self.assertRaises(KeyError, policy._authenticate, params, request)

    def test_auth_with_invalid_content_md5(self):
        policy = DigestAuthenticationPolicy("test", get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/authint",
                               HTTP_CONTENT_MD5="1B2M2Y8AsgTpgAmY7PhCfg==")
        params = get_challenge(policy, request)
        params = build_response(params, request, "tester", "testing",
                                qop="auth-int")
        request["HTTP_CONTENT_MD5"] = "8baNZjN6gc+g0gdhccuiqA=="
        self.assertEquals(policy._authenticate(request, params), False)

    # Tests for various cases in the remember() method.

    def test_remember_with_no_authorization(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request()
        self.assertEquals(policy.remember(request, "user"), None)

    def test_remember_with_no_next_nonce(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request()
        params = get_challenge(policy, request)
        params = build_response(params, request, "tester", "testing")
        self.assertEquals(policy.remember(request, "tester"), None)

    def test_remember_with_next_nonce(self):
        policy = DigestAuthenticationPolicy("test", nonce_manager=EasyNonceManager())
        request = make_request()
        params = get_challenge(policy, request)
        params = build_response(params, request, "tester", "testing")
        headers = policy.remember(request, "tester")
        self.assertEquals(headers[0][0], "Authentication-Info")

    # Tests for various cases in the challenge() method.

    def test_challenge(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request()
        response = policy.challenge_view(request)
        response = get_response(response, request)
        self.failUnless(response.startswith("401 Unauthorized"))
        self.failUnless("WWW-Authenticate: Digest" in response)

    def test_challenge_with_stale_nonce(self):
        policy = DigestAuthenticationPolicy("test")
        request = make_request()
        # Identify with a bad nonce to mark it as stale.
        params = get_challenge(policy, request)
        params["nonce"] += "STALE"
        params = build_response(params, request, "tester", "testing")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # The challenge should then include stale=TRUE
        app = policy.challenge_view(request)
        self.assertNotEqual(app, None)
        response = get_response(app, request)
        self.failUnless(response.startswith("401 Unauthorized"))
        self.failUnless('stale="TRUE"' in response)

    def test_challenge_with_extra_domains(self):
        policy = DigestAuthenticationPolicy("test", domain="http://example.com")
        request = make_request()
        app = policy.challenge_view(request)
        self.assertNotEqual(app, None)
        response = get_response(app, request)
        self.failUnless(response.startswith("401 Unauthorized"))
        self.failUnless("http://example.com" in response)


class TestDigestAuthHelpers(unittest.TestCase):
    """Testcases for the various digest-auth helper functions."""

    def test_validate_digest_parameters_qop(self):
        params = dict(scheme="Digest", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456", qop="auth",
                      uri="/my/page", cnonce="98765")
        # Missing "nc"
        self.failIf(validate_digest_parameters(params))
        params["nc"] = "0001"
        self.failUnless(validate_digest_parameters(params))
        # Wrong realm
        self.failIf(validate_digest_parameters(params, realm="otherrealm"))
        self.failUnless(validate_digest_parameters(params, realm="testrealm"))
        # Unknown qop
        params["qop"] = "super-duper"
        self.failIf(validate_digest_parameters(params))
        params["qop"] = "auth-int"
        self.failUnless(validate_digest_parameters(params))
        params["qop"] = "auth"
        # Unknown algorithm
        params["algorithm"] = "sha1"
        self.failIf(validate_digest_parameters(params))
        params["algorithm"] = "md5"
        self.failUnless(validate_digest_parameters(params))

    def test_validate_digest_parameters_legacy(self):
        params = dict(scheme="Digest", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456")
        # Missing "uri"
        self.failIf(validate_digest_parameters(params))
        params["uri"] = "/my/page"
        self.failUnless(validate_digest_parameters(params))
        # Wrong realm
        self.failIf(validate_digest_parameters(params, realm="otherrealm"))
        self.failUnless(validate_digest_parameters(params, realm="testrealm"))

    def test_validate_digest_uri(self):
        request = make_request(SCRIPT_NAME="/my", PATH_INFO="/page")
        params = dict(scheme="Digest", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456", qop="auth",
                      uri="/my/page", cnonce="98765", nc="0001")
        self.failUnless(validate_digest_uri(params, request))
        # Using full URI still works
        params["uri"] = "http://localhost/my/page"
        self.failUnless(validate_digest_uri(params, request))
        # Check that query-string is taken into account.
        params["uri"] = "http://localhost/my/page?test=one"
        self.failIf(validate_digest_uri(params, request))
        request["QUERY_STRING"] = "test=one"
        self.failUnless(validate_digest_uri(params, request))
        params["uri"] = "/my/page?test=one"
        self.failUnless(validate_digest_uri(params, request))
        # Check that only MSIE is allow to fudge on the query-string.
        params["uri"] = "/my/page"
        request["HTTP_USER_AGENT"] = "I AM FIREFOX I HAVE TO DO IT PROPERLY"
        self.failIf(validate_digest_uri(params, request))
        request["HTTP_USER_AGENT"] = "I AM ANCIENT MSIE PLZ HELP KTHXBYE"
        self.failUnless(validate_digest_uri(params, request))
        self.failIf(validate_digest_uri(params, request, msie_hack=False))
        params["uri"] = "/wrong/page"
        self.failIf(validate_digest_uri(params, request))
