# -*- coding: utf-8 -*-

import os
import json

from werkzeug.contrib.sessions import FilesystemSessionStore

from clastic import (redirect,
                     Middleware,
                     Application,
                     render_basic,
                     GetParamMiddleware)
from clastic.middleware.cookie import SignedCookieMiddleware

from mwoauth import get_request_token, get_access_token, make_api_call

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(CUR_DIR, 'config.dev.json')

DEFAULT_IW_PREFIX = 'mw'
DEFAULT_API_URL = 'https://www.mediawiki.org/w/api.php'
DEFAULT_BASE_URL = 'https://www.mediawiki.org/w/index.php?title=Special:OAuth'
DEFAULT_REQ_TOKEN_URL = DEFAULT_BASE_URL + '/initiate'
DEFAULT_AUTHZ_URL = DEFAULT_BASE_URL + '/authorize'
DEFAULT_TOKEN_URL = DEFAULT_BASE_URL + '/token'


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


def authorize(session, consumer_key, consumer_secret,
              authorize_token_url, request_token_url):
    req_token_key, req_token_secret = get_request_token(consumer_key,
                                                        consumer_secret,
                                                        request_token_url,
                                                        validate_certs=False)
    session['token_key'] = req_token_key
    session['token_secret'] = req_token_secret
    suffix = ('&oauth_token=%s&oauth_consumer_key=%s'
              % (req_token_key, consumer_key))
    redirect_url = authorize_token_url + suffix
    return redirect(redirect_url)


def authorize_complete(session,
                       consumer_key,
                       consumer_secret,
                       access_token_url,
                       oauth_verifier,
                       oauth_token):
    # TODO: assert this matches the oauth_token?
    req_token_key = session['token_key']
    req_token_secret = session['token_secret']

    acc_token_key, acc_token_secret = get_access_token(consumer_key,
                                                       consumer_secret,
                                                       req_token_key,
                                                       req_token_secret,
                                                       oauth_verifier,
                                                       access_token_url,
                                                       validate_certs=False)
    session['token_key'] = acc_token_key
    session['token_secret'] = acc_token_secret
    return True


def get_user_info(session, consumer_key, consumer_secret, api_url):
    params = {'action': 'query',
              'meta': 'userinfo'}
    access_token_key = session['token_key']
    access_token_secret = session['token_secret']
    content = make_api_call(consumer_key,
                            consumer_secret,
                            access_token_key,
                            access_token_secret,
                            'GET',
                            params,
                            api_url)
    return content


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
    ui_redirector = lambda context: redirect('/userinfo')
    routes = [('/', home, render_basic),
              ('/userinfo', get_user_info, render_basic),
              ('/auth/authorize', authorize, render_basic),
              ('/auth/callback', authorize_complete, ui_redirector)]

    resources = {'consumer_key': consumer_key,
                 'consumer_secret': consumer_secret,
                 'request_token_url': DEFAULT_REQ_TOKEN_URL,
                 'authorize_token_url': DEFAULT_AUTHZ_URL,
                 'access_token_url': DEFAULT_TOKEN_URL,
                 'api_url': DEFAULT_API_URL}

    middlewares = [GetParamMiddleware(['oauth_verifier', 'oauth_token']),
                   SignedCookieMiddleware(secret_key=consumer_secret),
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
