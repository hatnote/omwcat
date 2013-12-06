# -*- coding: utf-8 -*-

import json
import time
import urllib

import httplib2
import oauth2 as oauth

from pprint import pformat

# general flow:
# get request token, save in session
# redirect to auth url
# retrieve request token from session
# using verifier, build access token request
# get access token, save to session


def _get_realm(url):
    # not sure this is necessary, but just to be on the safe side
    schema, rest = urllib.splittype(url)
    hierpart = '//' if rest.startswith('//') else ''
    host, rest = urllib.splithost(rest)
    return schema + ':' + hierpart + host


def make_api_call(consumer_key,
                  consumer_secret,
                  access_token_key,
                  access_token_secret,
                  method,
                  params,
                  api_url,
                  body='',
                  headers=None):

    headers = dict(headers or {})
    method = method.upper()
    params = dict(params, format='json')
    if method == 'GET':
        full_url = api_url + "?" + urllib.urlencode(params)
        body = ''
        is_form_encoded = False
    elif method == 'POST':
        full_url = api_url
        body = urllib.urlencode(params)
        is_form_encoded = True
    else:
        raise ValueError('unsupported HTTP method %r' % method)

    consumer = oauth.Consumer(consumer_key, consumer_secret)
    token = oauth.Token(access_token_key, access_token_secret)
    client = oauth.Client(consumer, token)
    client.disable_ssl_certificate_validation = True

    req = oauth.Request.from_consumer_and_token(consumer,
                                                token,
                                                method,
                                                full_url,
                                                params,
                                                body,
                                                is_form_encoded)
    req.sign_request(client.method, consumer, token)  # wtf
    realm = _get_realm(full_url)
    headers.update(req.to_header(realm=realm))

    resp, content = httplib2.Http.request(client, full_url,
                                          method=method,
                                          body=body,
                                          headers=headers)
    return content


def get_request_token(consumer_key,
                      consumer_secret,
                      request_token_url,
                      validate_certs=True):
    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer)
    client.disable_ssl_certificate_validation = not validate_certs
    params = {'format': 'json',
              'oauth_version': '1.0',
              'oauth_nonce': oauth.generate_nonce(),
              'oauth_timestamp': int(time.time()),
              'oauth_callback': 'oob'}  # :/
    req = oauth.Request('GET', request_token_url, params)
    signing_method = oauth.SignatureMethod_HMAC_SHA1()
    req.sign_request(signing_method, consumer, None)
    full_url = req.to_url()
    resp, content = httplib2.Http.request(client, full_url, method='GET')
    try:
        resp_dict = json.loads(content)
        req_token_key, req_token_secret = resp_dict['key'], resp_dict['secret']
    except:
        raise ValueError('request token step failed: %s\n\nheaders, etc.: %s'
                         % (content, pformat(resp)))
    return req_token_key, req_token_secret


def get_access_token(consumer_key,
                     consumer_secret,
                     req_token_key,
                     req_token_secret,
                     verifier,
                     access_token_url,
                     validate_certs=True):
    consumer = oauth.Consumer(consumer_key, consumer_secret)
    request_token = oauth.Token(req_token_key, req_token_secret)
    client = oauth.Client(consumer, request_token)
    client.disable_ssl_certificate_validation = not validate_certs

    params = {'format': 'json',
              'oauth_version': '1.0',
              'oauth_nonce': oauth.generate_nonce(),
              'oauth_timestamp': int(time.time()),
              'oauth_verifier': verifier,
              'oauth_callback': 'oob'}
    # wow, all those keys are really necessary
    # otherwise you get a really opaque '{"error":"mwoauth-oauth-exception"}'
    req = oauth.Request('GET', access_token_url, params)
    signing_method = oauth.SignatureMethod_HMAC_SHA1()
    req.sign_request(signing_method, consumer, request_token)
    full_url = req.to_url()
    # wow
    resp, content = httplib2.Http.request(client, full_url, method='GET')
    try:
        resp_dict = json.loads(content)
        acc_token_key, acc_token_secret = resp_dict['key'], resp_dict['secret']
    except:
        raise ValueError('access token step failed: %s\n\nheaders, etc.: %s'
                         % (content, pformat(resp)))
    return acc_token_key, acc_token_secret
