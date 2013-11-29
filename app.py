# -*- coding: utf-8 -*-

import os
import json
import time
from pprint import pformat

import httplib2
import oauth2 as oauth
from werkzeug.contrib.sessions import FilesystemSessionStore

from clastic import (redirect,
                     Middleware,
                     Application,
                     default_response,
                     GetParamMiddleware)
from clastic.middleware.cookie import SignedCookieMiddleware

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(CUR_DIR, 'config.json')

DEFAULT_IW_PREFIX = 'mw'
DEFAULT_API_URL = 'https://test.wikipedia.org/w/api.php'
DEFAULT_BASE_URL = 'https://www.mediawiki.org/w/index.php?title=Special:OAuth'
DEFAULT_REQ_TOKEN_URL = DEFAULT_BASE_URL + '/initiate'
DEFAULT_AUTHZ_URL = DEFAULT_BASE_URL + '/authorize'


class SessionTokenMiddleware(Middleware):
    provides = ('token_key', 'token_secret')

    def request(self, next, cookie):
        return next(token_key=cookie.get('token_key'),
                    token_secret=cookie.get('token_secret'))


class SessionMiddleware(Middleware):
    provides = ('session',)

    def __init__(self, session_store=None):
        if session_store is None:
            session_store = FilesystemSessionStore()
        self.session_store = session_store

    def request(self, next, cookie):
        session_id = cookie.get('session_id')
        if session_id is None:
            session = self.session_store.new()
        else:
            session = self.session_store.get(session_id)
        ret = next(session=session)
        if session.should_save:
            self.session_store.save(session)
            cookie['session_id'] = session.sid
        return ret


def authorize(cookie, consumer_key, consumer_secret, token_key, token_secret):
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
    cookie['token_key'] = new_token_key
    #cookie['token_secret'] = new_token_secret  # store this somewhere
    suffix = ('&oauth_token=%s&oauth_consumer_key=%s'
              % (new_token_key, consumer_key))
    redirect_url = DEFAULT_AUTHZ_URL + suffix
    return redirect(redirect_url)


def home(session):
    import time
    times = session.setdefault('times', [])
    times.append(time.time())
    if len(times) < 2:
        return 'Waiting for another beat...'
    elif len(times) > 10:
        times = times[-10:]
    total_time = times[-1] - times[0]
    bps = total_time / len(times)
    session['times'] = times
    return '%.2f beats per minute' % (60 / bps)


def create_app(consumer_key, consumer_secret):
    routes = [('/', home, default_response),
              ('/auth/authorize', authorize, default_response)]

    resources = {'consumer_key': consumer_key,
                 'consumer_secret': consumer_secret}

    middlewares = [GetParamMiddleware(['oauth_verifier']),
                   SignedCookieMiddleware(),
                   SessionTokenMiddleware(),
                   SessionMiddleware()]
    return Application(routes, resources, middlewares=middlewares)


def main(config_path=None):
    config_path = config_path or DEFAULT_CONFIG_PATH
    config = json.load(open(config_path))
    consumer_key = config['consumer_key']
    consumer_secret = config['consumer_secret']
    app = create_app(consumer_key, consumer_secret)
    app.serve()


if __name__ == '__main__':
    main()
