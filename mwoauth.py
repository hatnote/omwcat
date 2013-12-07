# -*- coding: utf-8 -*-

import json
import time
import urllib

import httplib2
import oauth2 as oauth

import oauthlib
from oauthlib.oauth1 import Client as OAClient
from oauthlib.oauth1 import SIGNATURE_TYPE_QUERY

from pprint import pformat

# general flow:
# get request token, save in session
# redirect to auth url
# retrieve request token from session
# using verifier, build access token request
# get access token, save to session

try:
    oauthlib.common.urlencoded.add(':')  # idc anymore
    oauthlib.common.urlencoded.add('/')  # idc anymore
except:
    raise


def make_api_call(consumer_key,
                  consumer_secret,
                  access_token_key,
                  access_token_secret,
                  method,
                  params,
                  api_url,
                  body=None,
                  headers=None):

    headers = dict(headers or {})
    method = method.upper()
    params = dict(params, format='json')
    if method == 'GET':
        full_url = api_url + "?" + urllib.urlencode(params)
    elif method == 'POST':
        full_url = api_url
        body = urllib.urlencode(params)
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    else:
        raise ValueError('unsupported HTTP method %r' % method)

    client = OAClient(consumer_key, client_secret=consumer_secret,
                      resource_owner_key=access_token_key,
                      resource_owner_secret=access_token_secret)
    full_url, headers, body = client.sign(full_url, method, body, headers)

    client = httplib2.Http()
    client.disable_ssl_certificate_validation = True

    resp, content = client.request(full_url,
                                   method=method,
                                   body=body,
                                   headers=headers)
    return content


def get_request_token(consumer_key,
                      consumer_secret,
                      request_token_url,
                      validate_certs=True):
    method = 'GET'
    params = {'format': 'json', 'oauth_callback': 'oob'}
    full_url = request_token_url + "&" + urllib.urlencode(params)
    client = OAClient(consumer_key, client_secret=consumer_secret,
                      signature_type=SIGNATURE_TYPE_QUERY)
    full_url, headers, body = client.sign(full_url, method)

    client = httplib2.Http()
    client.disable_ssl_certificate_validation = True
    resp, content = client.request(full_url, method=method)
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
