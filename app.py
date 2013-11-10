# -*- coding: utf-8 -*-
from clastic import Application, default_response, redirect
from clastic.middleware.session import CookieSessionMiddleware
from argparse import ArgumentParser


def authorize():
    return 'yo'


def create_app():
    routes = [('/', lambda: 'hi', default_response),
              ('/auth/authorize', authorize, default_response)]

    resources = {}
    middlewares = [CookieSessionMiddleware()]
    return Application(routes, resources, middlewares=middlewares)


def main():
    app = create_app()
    app.serve()


if __name__ == '__main__':
    main()
