# -*- coding: utf-8 -*-

import os
import json
import time
from pprint import pformat

import httplib2
import oauth2 as oauth
from clastic import (redirect,
                     Middleware,
                     Application,
                     default_response,
                     GetParamMiddleware)
from clastic.middleware.session import CookieSessionMiddleware

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(CUR_DIR), 'config.json')

DEFAULT_IW_PREFIX = 'mw'
DEFAULT_API_URL = 'https://test.wikipedia.org/w/api.php'
DEFAULT_BASE_URL = 'https://www.mediawiki.org/w/index.php?title=Special:OAuth'
DEFAULT_REQ_TOKEN_URL = DEFAULT_BASE_URL + '/initiate'
DEFAULT_AUTHZ_URL = DEFAULT_BASE_URL + '/authorize'


class SessionTokenMiddleware(Middleware):
    provides = ('token_key', 'token_secret')

    def request(self, next, session):
        return next(token_key=session.get('token_key'),
                    token_secret=session.get('token_secret'))


def authorize(session, consumer_key, consumer_secret, token_key, token_secret):
    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer)
    client.disable_ssl_certificate_validation = True
    params = {'format': 'json',
              'oauth_version': '1.0',
              'oauth_nonce': oauth.generate_nonce(),
              'oauth_timestamp': int(time.time()),
              'oauth_callback': 'oob'}  # :/
    req = oauth.Request('GET', DEFAULT_REQ_TOKEN_URL, params)
    signing_method = oauth.SignatureMethod_HMAC_SHA1()
    req.sign_request(signing_method, consumer, None)
    full_url = req.to_url()
    # wow
    resp, content = httplib2.Http.request(client, full_url, method='GET')
    try:
        resp_dict = json.loads(content)
        new_token_key, new_token_secret = resp_dict['key'], resp_dict['secret']
    except:
        return ('request token step failed: %s\n\nheaders, etc.: %s'
                % (content, pformat(resp)))
    session['token_key'] = new_token_key
    #session['token_secret'] = new_token_secret  # store this somewhere
    suffix = ('&oauth_token=%s&oauth_consumer_key=%s'
              % (new_token_key, consumer_key))
    redirect_url = DEFAULT_AUTHZ_URL + suffix
    return redirect(redirect_url)


def create_app(config_path=None):
    routes = [('/', lambda: 'hi', default_response),
              ('/auth/authorize', authorize, default_response)]
    config_path = config_path or DEFAULT_CONFIG_PATH
    config = json.load(open(config_path))
    resources = {'config': config,
                 'consumer_key': config['consumer_key'],
                 'consumer_secret': config['consumer_secret']}

    middlewares = [GetParamMiddleware(['oauth_verifier']),
                   CookieSessionMiddleware(),
                   SessionTokenMiddleware()]
    return Application(routes, resources, middlewares=middlewares)


def main():
    app = create_app()
    app.serve()


if __name__ == '__main__':
    main()
