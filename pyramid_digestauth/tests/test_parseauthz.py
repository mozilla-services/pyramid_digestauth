import unittest

from pyramid_digestauth.parseauthz import parse_authz_header
from pyramid.testing import DummyRequest


def parse_authz_value(authz):
    environ = {"HTTP_AUTHORIZATION": authz}
    req = DummyRequest(environ=environ)
    return parse_authz_header(req)


class TestParseAuthz(unittest.TestCase):
    """Testcases for parsing the Authorization header."""

    def test_parse_authz_value(self):
        # Test parsing of a single unquoted parameter.
        params = parse_authz_value('Digest realm=hello')
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['realm'], 'hello')

        # Test parsing of multiple parameters with mixed quotes.
        params = parse_authz_value('Digest test=one, again="two"')
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], 'one')
        self.assertEquals(params['again'], 'two')

        # Test parsing of an escaped quote and empty string.
        params = parse_authz_value('Digest test="\\"",again=""')
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], '"')
        self.assertEquals(params['again'], '')

        # Test parsing of embedded commas, escaped and non-escaped.
        params = parse_authz_value('Digest one="1\\,2", two="3,4"')
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['one'], '1,2')
        self.assertEquals(params['two'], '3,4')

        # Test parsing on various malformed inputs
        self.assertRaises(ValueError, parse_authz_value, "")
        self.assertRaises(ValueError, parse_authz_value, " ")
        self.assertRaises(ValueError, parse_authz_value,
                          'Broken raw-token')
        self.assertRaises(ValueError, parse_authz_value,
                          'Broken realm="unclosed-quote')
        self.assertRaises(ValueError, parse_authz_value,
                          'Broken realm=unopened-quote"')
        self.assertRaises(ValueError, parse_authz_value,
                          'Broken realm="unescaped"quote"')
        self.assertRaises(ValueError, parse_authz_value,
                          'Broken realm="escaped-end-quote\\"')
        self.assertRaises(ValueError, parse_authz_value,
                          'Broken realm="duplicated",,what=comma')
