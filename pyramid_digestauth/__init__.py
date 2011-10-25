# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is pyramid_digestauth
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (ryan@rfk.id.au)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""

A Pyramid plugin for authentication via HTTP-Digest-Auth:

    http://tools.ietf.org/html/rfc2617

"""

from zope.interface import implements

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated, remember, forget
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.response import Response
from pyramid.util import DottedNameResolver

from pyramid_digestauth.noncemanager import SignedNonceManager
from pyramid_digestauth.parseauthz import parse_authz_header
from pyramid_digestauth.utils import (validate_digest_parameters,
                                      validate_digest_uri,
                                      validate_digest_nonce,
                                      calculate_pwdhash,
                                      check_digest_response)


# WSGI environ key used to indicate a stale nonce.
_ENVKEY_STALE_NONCE = "pyramid_digestauth.stale_nonce"

# WSGI environ key used to cache a validated digest response.
_ENVKEY_VALID_RESPONSE = "pyramid_digestauth.valid_response"

# WSGI environ key used to cache parsed auth header parameters.
_ENVKEY_PARSED_AUTHZ = "pyramid_digestauth.parsed_authz"


class DigestAuthenticationPolicy(object):
    """A pyramid plugin for authentication via HTTP-Digest-Auth.

    This plugin provides a pyramid IAuthenticationPolicy implementing the
    HTTP-Digest-Auth protocol:

        http://tools.ietf.org/html/rfc2617

    This class implements fairly complete support for the protocol as defined
    in RFC-2167.  Specifically:

        * both qop="auth" and qop="auth-int" modes
        * compatability mode for legacy clients
        * client nonce-count checking
        * next-nonce generation via the Authentication-Info header

    The following optional parts of the specification are not supported:

        * MD5-sess, or any hash algorithm other than MD5
        * mutual authentication via the Authentication-Info header

    Also, for qop="auth-int" mode, this class assumes that the request
    contains a Content-MD5 header and that this header is validated by some
    other component of the system (as it would be very rude for an auth
    policy to consume the request body to calculate this header itself).

    To implement nonce generation, storage and expiration, this class
    uses a helper object called a "nonce manager".  This allows the details
    of nonce management to be modified to meet the security needs of your
    deployment.  The default implementation (SignedNonceManager) should be
    suitable for most purposes.
    """

    implements(IAuthenticationPolicy)

    def __init__(self, realm, nonce_manager=None, domain=None, qop=None,
                 get_password=None, get_pwdhash=None, groupfinder=None):
        if nonce_manager is None:
            nonce_manager = SignedNonceManager()
        if qop is None:
            qop = "auth"
        self.realm = realm
        self.nonce_manager = nonce_manager
        self.domain = domain
        self.qop = qop
        self.get_password = get_password
        self.get_pwdhash = get_pwdhash
        self.groupfinder = groupfinder

    @classmethod
    def from_settings(cls, settings={}, prefix="digestauth.", **kwds):
        """Create a new DigestAuthenticationPolicy from a settings dict."""
        # Grab out all the settings keys that start with our prefix.
        auth_settings = {}
        for name, value in settings.iteritems():
            if not name.startswith(prefix):
                continue
            auth_settings[name[len(prefix):]] = value
        # Update with any additional keyword arguments.
        auth_settings.update(kwds)
        # Now look for specific keys of interest.
        maybe_resolve = DottedNameResolver(None).maybe_resolve
        # You must specify a realm.
        if "realm" not in auth_settings:
            raise ValueError("pyramid_digestauth: you must specify the realm")
        # NonceManager can be specified as class or instance name.
        nonce_manager = maybe_resolve(auth_settings.get("nonce_manager"))
        if callable(nonce_manager):
            nonce_manager = nonce_manager()
        auth_settings["nonce_manager"] = nonce_manager
        # get_password can be dotted name of a callable
        get_password = maybe_resolve(auth_settings.get("get_password"))
        if get_password is not None:
            assert callable(get_password)
        auth_settings["get_password"] = get_password
        # get_pwdhash can be dotted name of a callable
        get_pwdhash = maybe_resolve(auth_settings.get("get_pwdhash"))
        if get_pwdhash is not None:
            assert callable(get_pwdhash)
        auth_settings["get_pwdhash"] = get_pwdhash
        # groupfinder can be dotted name of a callable
        groupfinder = maybe_resolve(auth_settings.get("groupfinder"))
        if groupfinder is not None:
            assert callable(groupfinder)
        auth_settings["groupfinder"] = groupfinder
        # OK, the rest should just be keyword arguments.
        return cls(**auth_settings)

    def authenticated_userid(self, request):
        """Get the authenticated userid for this request.

        When using HTTP-Digest-Auth, this requires calculating the expected
        digest response using the user's password hash, and comparing it to
        the response returned in the Authorization header.
        """
        params = self._get_auth_params(request)
        if params is None:
            return None
        if not self._authenticate(request, params):
            return None
        username = params["username"]
        if self.groupfinder is not None:
            if self.groupfinder(username) is None:
                return None
        return username

    def unauthenticated_userid(self, request):
        """Get the unauthenticated userid for this request.

        When using HTTP-Digest-Auth, this involves looking in the Authorization
        header to find the reported username.
        """
        params = self._get_auth_params(request)
        if params is None:
            return None
        return params["username"]

    def effective_principals(self, request):
        """Get the list of effective principals for this request."""
        principals = [Everyone]
        params = self._get_auth_params(request)
        if params is None:
            return principals
        if not self._authenticate(request, params):
            return principals
        username = params["username"]
        if self.groupfinder is None:
            groups = ()
        else:
            groups = self.groupfinder(username)
            if groups is None:
                return principals
        principals.append(username)
        principals.append(Authenticated)
        principals.extend(groups)
        return principals

    def remember(self, request, principal, **kw):
        """Remember the authenticated identity.

        This method can be used to pre-emptively send an updated nonce to
        the client as part of a successful response.  It is otherwise a
        no-op; the user-agent is supposed to remember the provided credentials
        and automatically send an authorization header with future requests.
        """
        params = self._get_auth_params(request)
        if params is None:
            return None
        nonce = params["nonce"]
        next_nonce = self.nonce_manager.get_next_nonce(nonce, request)
        if next_nonce is None:
            return None
        return [("Authentication-Info", 'nextnonce="%s"' % (next_nonce,))]

    def forget(self, request):
        """Forget the authenticated identity.

        For digest auth this is equivalent to sending a new challenge header,
        which should cause the user-agent to re-prompt for credentials.
        """
        return self._get_challenge_headers(request, check_stale=False)

    def challenge_view(self, request):
        """View that challenges for credentials with a "401 Unauthorized".

        This method can be used as a pyramid "forbidden view" in order to
        challenge for auth credentials when necessary.
        """
        headerlist = [("Content-Type", "text/plain")]
        headerlist.extend(self._get_challenge_headers(request))
        return Response("Unauthorized", status="401 Unauthorized",
                        headerlist=headerlist)

    def _get_challenge_headers(self, request, check_stale=True):
        """Get headers necessary for a fresh digest-auth challenge.

        This method generates a new digest-auth challenge for the given
        request, including a fresh nonce.  If the environment is marked
        as having a stale nonce then this is indicated in the challenge.
        """
        params = {}
        params["realm"] = self.realm
        if self.domain is not None:
            params["domain"] = self.domain
        # Escape any special characters in those values, so we can send
        # them as quoted-strings.  The extra values added below are under
        # our control so we know they don't contain quotes.
        for key, value in params.iteritems():
            params[key] = value.replace('"', '\\"')
        # Set various internal parameters.
        params["qop"] = self.qop
        params["nonce"] = self.nonce_manager.generate_nonce(request)
        params["algorithm"] = "MD5"
        # Mark the nonce as stale if told so by the environment.
        # NOTE:  The RFC says the server "should only set stale to TRUE if
        # it receives a request for which the nonce is invalid but with a
        # valid digest for that nonce".  But we can't necessarily check the
        # password at this stage, and it's only a "should", so don't bother.
        if check_stale and request.environ.get(_ENVKEY_STALE_NONCE):
            params["stale"] = "TRUE"
        # Construct the final header as quoted-string k/v pairs.
        value = ", ".join('%s="%s"' % itm for itm in params.iteritems())
        return [("WWW-Authenticate", "Digest " + value)]

    def _get_auth_params(self, request):
        """Extract digest-auth parameters from the request.

        This method extracts digest-auth parameters from the Authorization
        header and returns them as a dict.  If they are missing then None
        is returned.
        """
        #  Parse the Authorization header, using cached version if possible.
        if _ENVKEY_PARSED_AUTHZ in request.environ:
            params = request.environ[_ENVKEY_PARSED_AUTHZ]
        else:
            try:
                params = parse_authz_header(request)
            except ValueError:
                params = None
            request.environ[_ENVKEY_PARSED_AUTHZ] = params
        # Check that they're valid digest-auth parameters.
        if params is None:
            return None
        if params["scheme"].lower() != "digest":
            return None
        if not validate_digest_parameters(params, self.realm):
            return None
        # Check that the digest is applied to the correct URI.
        if not validate_digest_uri(params, request):
            return None
        # Check that the provided nonce is valid.
        # If this looks like a stale request, mark it in the request
        # so we can include that information in the challenge.
        if not validate_digest_nonce(params, request, self.nonce_manager):
            request.environ[_ENVKEY_STALE_NONCE] = True
            return None
        return params

    def _authenticate(self, request, params):
        """Authenticate digest-auth params against known passwords.

        This method checks the provided response digest to authenticate the
        request, using either the "get_password" or "get_pwdhash" callback
        to obtain the user's verifier.
        """
        username = params["username"]
        realm = params["realm"]
        response = params["response"]
        # Quick check if we've already validated these params.
        if request.environ.get(_ENVKEY_VALID_RESPONSE) == response:
            return True
        # Obtain the pwdhash via one of the callbacks.
        if self.get_pwdhash is not None:
            pwdhash = self.get_pwdhash(username, realm)
        elif self.get_password is not None:
            password = self.get_password(username)
            pwdhash = calculate_pwdhash(username, password, realm)
        else:
            return False
        # Validate the digest response.
        if not check_digest_response(params, request, pwdhash=pwdhash):
            return False
        # Cache the successful authentication.
        request.environ[_ENVKEY_VALID_RESPONSE] = response
        return True


def includeme(config):
    """Include default digestauth settings into a pyramid config.

    This function provides a hook for pyramid to include the default settings
    for HTTP-Digest-Auth.  Activate it like so:

        config.include("pyramid_ipauth")

    This will activate a DigestAuthenticationplicy instance with settings taken
    from the the application settings as follows:

        * digestauth.realm:           realm string for auth challenge header
        * digestauth.qop:             qop string for auth challenge header
        * digestauth.nonce_manager:   name of NonceManager class to use
        * digestauth.domain:          domain string for auth challenge header
        * digestauth.get_password:    name of password-retrieval function
        * digestauth.get_pwdhash:     name of pwdhash-retrieval function
        * digestauth.groupfinder:     name of group-finder callback function

    It will also activate:

        * a forbidden view that will challenge for digest-auth credentials.

    """
    # Grab the pyramid-wide settings, to look for any auth config.
    settings = config.get_settings().copy()
    # Use the settings to construct an AuthenticationPolicy.
    authn_policy = DigestAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)
    # Hook up a default AuthorizationPolicy.
    # You can't have one without the other, and  ACLAuthorizationPolicy is
    # usually what you want.  If the app configures one explicitly then this
    # will get overridden.
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)
    # Add forbidden view to challenge for auth credentials.
    config.add_view(authn_policy.challenge_view,
                    context="pyramid.exceptions.Forbidden")
