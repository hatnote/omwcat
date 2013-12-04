# -*- coding: utf-8 -*-

"""
MediaWiki OAuth Middleware (mwoauthmw??)

Similar to (and partially derived from) flask_oauth and related
implementations but with less tight coupling to flask.

flask_oauth copyright 2010 by Armin Ronacher, BSD-licensed.
"""

import os
import json
import time
from urlparse import urljoin

import oauth2
import httplib2
from werkzeug import (url_decode, url_encode, url_quote,
                      parse_options_header, Headers)


_etree = None


def get_etree():
    """Return an elementtree implementation.  Prefers lxml"""
    global _etree
    if _etree is None:
        try:
            from lxml import etree as _etree
        except ImportError:
            try:
                from xml.etree import cElementTree as _etree
            except ImportError:
                try:
                    from xml.etree import ElementTree as _etree
                except ImportError:
                    raise TypeError('lxml or etree not found')
    return _etree


def parse_response(resp, content, strict=False):
    ct, options = parse_options_header(resp['content-type'])
    if ct in ('application/json', 'text/javascript'):
        return json.loads(content)
    elif ct in ('application/xml', 'text/xml'):
        # technically, text/xml is ascii based but because many
        # implementations get that wrong and utf-8 is a superset
        # of utf-8 anyways, so there is not much harm in assuming
        # utf-8 here
        charset = options.get('charset', 'utf-8')
        return get_etree().fromstring(content.decode(charset))
    elif ct != 'application/x-www-form-urlencoded':
        if strict:
            return content
    charset = options.get('charset', 'utf-8')
    return url_decode(content, charset=charset).to_dict()


def add_query(url, args):
    if not args:
        return url
    return url + ('?' in url and '&' or '?') + url_encode(args)


def encode_request_data(data, format):
    if format is None:
        return data, None
    elif format == 'json':
        return json.dumps(data or {}), 'application/json'
    elif format == 'urlencoded':
        return url_encode(data or {}), 'application/x-www-form-urlencoded'
    raise TypeError('Unknown format %r' % format)


class OAuthResponse(object):
    """Contains the response sent back from an OAuth protected remote
    application.
    """

    def __init__(self, resp, content):
        #: a :class:`~werkzeug.Headers` object with the response headers
        #: the application sent.
        self.headers = Headers(resp)
        #: the raw, unencoded content from the server
        self.raw_data = content
        #: the parsed content from the server
        self.data = parse_response(resp, content, strict=True)

    @property
    def status(self):
        """The status code of the response."""
        return self.headers.get('status', type=int)


class OAuthClient(oauth2.Client):
    def request_new_token(self, uri, callback=None, params={}):
        base_params = {'format': 'json',
                       'oauth_version': '1.0',
                       'oauth_nonce': oauth2.generate_nonce(),
                       'oauth_timestamp': int(time.time()),
                       'oauth_callback': 'oob'}  # :/
        params = dict(base_params, **params)
        req = oauth2.Request('GET', uri, params)
        signing_method = oauth2.SignatureMethod_HMAC_SHA1()
        req.sign_request(signing_method, self.consumer, None)
        full_url = req.to_url()
        # wow
        return httplib2.Http.request(self, full_url, method='GET')


class OAuthException(RuntimeError):
    """Raised if authorization fails for some reason."""
    def __init__(self, message, data=None):
        #: A helpful error message for debugging
        self.message = message
        #: If available, the parsed data from the remote API that can be
        #: used to pointpoint the error.
        self.data = data

    def __str__(self):
        return self.message.encode('utf-8')

    def __unicode__(self):
        return self.message


class InvalidOAuthResponse(OAuthException):
    pass


class OAuthTokenGenerationError(OAuthException):
    pass


def _status_okay(resp):
    """Given request data, checks if the status is okay."""
    try:
        return int(resp['status']) in (200, 201)
    except ValueError:
        return False


class OAuthRemoteApp(object):
    """Represents a remote application.

    :param name: then name of the remote application
    :param request_token_url: the URL for requesting new tokens
    :param access_token_url: the URL for token exchange
    :param authorize_url: the URL for authorization
    :param consumer_key: the application specific consumer key
    :param consumer_secret: the application specific consumer secret
    :param request_token_params: an optional dictionary of parameters
                                 to forward to the request token URL
                                 or authorize URL depending on oauth
                                 version.
    :param access_token_params: an option diction of parameters to forward to
                                the access token URL
    :param access_token_method: the HTTP method that should be used
                                for the access_token_url.  Defaults
                                to ``'GET'``.
    """

    def __init__(self,
                 name,
                 base_url,
                 request_token_url,
                 access_token_url, authorize_url,
                 consumer_key, consumer_secret,
                 request_token_params=None,
                 access_token_params=None,
                 access_token_method='GET',
                 verify_certs=True):
        #: the `base_url` all URLs are joined with.
        self.base_url = base_url
        self.name = name
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.tokengetter_func = None
        self.request_token_params = request_token_params or {}
        self.access_token_params = access_token_params or {}
        self.access_token_method = access_token_method
        self._consumer = oauth2.Consumer(self.consumer_key,
                                         self.consumer_secret)
        self._client = OAuthClient(self._consumer)
        self.verify_certs = verify_certs
        if not self.verify_certs:
            self._client.disable_ssl_certificate_validation = True

    def get(self, *args, **kwargs):
        """Sends a ``GET`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'GET'
        return self.request(*args, **kwargs)

    def post(self, *args, **kwargs):
        """Sends a ``POST`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'POST'
        return self.request(*args, **kwargs)

    def put(self, *args, **kwargs):
        """Sends a ``PUT`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'PUT'
        return self.request(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Sends a ``DELETE`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'DELETE'
        return self.request(*args, **kwargs)

    def expand_url(self, url):
        return urljoin(self.base_url, url)

    def generate_request_token(self, callback=None):
        #if callback is not None:
        #    callback = urljoin(request.url, callback)
        expanded_url = self.expand_url(self.request_token_url)
        client = self._client
        resp, content = client.request_new_token(expanded_url,
                                                 callback,
                                                 self.request_token_params)
        if not _status_okay(resp):
            raise OAuthTokenGenerationError('Failed to generate request token')
        data = parse_response(resp, content)
        try:
            oauth_token, oauth_token_secret = data['key'], data['secret']
            return oauth_token, oauth_token_secret
        except KeyError:
            raise OAuthTokenGenerationError('Invalid token response from %s'
                                            % self.name, data=data)

    def make_client(self, token=None):
        """Creates a new `oauth2` Client object with the token attached.
        Usually you don't have to do that but use the :meth:`request`
        method instead.
        """
        ret = oauth2.Client(self._consumer, self.get_request_token(token))
        if not self.verify_certs:
            ret.disable_ssl_certificate_validation = True
        return ret

    def request(self, url, token, data="", headers=None, format='urlencoded',
                method='GET', content_type=None):
        """Sends a request to the remote server with OAuth tokens attached.
        The `url` is joined with :attr:`base_url` if the URL is relative.

        .. versionadded:: 0.12
           added the `token` parameter.

        :param url: where to send the request to
        :param token: token as pulled from the session or somesuch
        :param data: the data to be sent to the server.  If the request method
                     is ``GET`` the data is appended to the URL as query
                     parameters, otherwise encoded to `format` if the format
                     is given.  If a `content_type` is provided instead, the
                     data must be a string encoded for the given content
                     type and used as request body.
        :param headers: an optional dictionary of headers.
        :param format: the format for the `data`.  Can be `urlencoded` for
                       URL encoded data or `json` for JSON.
        :param method: the HTTP request method to use.
        :param content_type: an optional content type.  If a content type is
                             provided, the data is passed as it and the
                             `format` parameter is ignored.

        :return: an :class:`OAuthResponse` object.
        """
        headers = dict(headers or {})
        client = self.make_client(token)
        url = self.expand_url(url)
        if method == 'GET':
            assert format == 'urlencoded'
            if data:
                url = add_query(url, data)
                data = ""
        else:
            if content_type is None:
                data, content_type = encode_request_data(data, format)
            if content_type is not None:
                headers['Content-Type'] = content_type
        return OAuthResponse(*client.request(url, method=method,
                                             body=data or '',
                                             headers=headers))


def login(mwoauth):
    redirector = mwoauth.authorize()
    redirector.headers['Location'] += ("&oauth_consumer_key=%s"
                                       % mwoauth.consumer_key)
    return redirector


def handle_oauth1_response(self, request, mwoauth):
    oauth_verifier = request.args.get('oauth_verifier')
    if oauth_verifier is None:
        raise OAuthException()
    client = mwoauth.make_client()
    expanded_url = mwoauth.expand_url(mwoauth.access_token_url)
    verify_url = '%s&oauth_verifier=%s' % (expanded_url, oauth_verifier)
    resp, content = client.request(verify_url, mwoauth.access_token_method)
    print resp, content
    data = parse_response(resp, content)
    if not _status_okay(resp):
        raise InvalidOAuthResponse('Invalid response from ' + mwoauth.name,
                                   data=data)
    return data


ROOT_SITE_URL = 'https://www.mediawiki.org/w'
BASE_URL = ROOT_SITE_URL.rstrip('/') + '/index.php'
ACCESS_TOKEN_URL = BASE_URL + "?title=Special:OAuth/token"
AUTHORIZE_URL = BASE_URL + '?title=Special:OAuth/authorize'
REQ_TOKEN_PARAMS = {'title': 'Special:OAuth/initiate',
                    'oauth_callback': 'oob'}
C_KEY = '42c3cf1f0c83439abc8b61d0df52a197'
C_SECRET = ''


mwoauth = OAuthRemoteApp('mw.org',
                         base_url=BASE_URL,
                         request_token_url=BASE_URL,
                         request_token_params=REQ_TOKEN_PARAMS,
                         access_token_url=ACCESS_TOKEN_URL,
                         authorize_url=AUTHORIZE_URL,
                         consumer_key=C_KEY,
                         consumer_secret=C_SECRET,
                         verify_certs=False)


mwoauth.generate_request_token()
