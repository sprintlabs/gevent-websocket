"""
This example generates random data and plots a graph in the browser.

Run it using Gevent directly using:
    $ python plot_grapg.py

Or with an Gunicorn wrapper:
    $ gunicorn -k "geventwebsocket.gunicorn.workers.GeventWebSocketWorker" \
        plot_graph:app
"""

import os.path
import random

import gevent
from gevent import pywsgi

import geventwebsocket
from geventwebsocket.handler import WebSocketHandler


def handle(ws):
    """
    This is the websocket handler function. Note that we can dispatch based on
    path in here, too.
    """
    if ws.path == "/echo":
        while True:
            m = ws.receive()
            if m is None:
                break
            ws.send(m)

    elif ws.path == "/data":
        try:
            for i in xrange(10000):
                ws.send("0 %s %s\n" % (i, random.random()))
                gevent.sleep(0.1)
        except geventwebsocket.WebSocketError as ex:
            print "%s: %s" % (ex.__class__.__name__, ex)


def app(environ, start_response):
    if environ["PATH_INFO"] == "/":
        start_response("200 OK", [("Content-Type", "text/html")])

        base_dir = os.path.dirname(__file__)

        with open(os.path.join(base_dir, 'plot_graph.html'), 'rt') as fp:
            return fp.readlines()

    elif environ["PATH_INFO"] in ("/data", "/echo"):
        handle(environ["wsgi.websocket"])
    else:
        start_response("404 Not Found", [])

        return []


if __name__ == "__main__":
    server = pywsgi.WSGIServer(
        ("", 8000), app,
        handler_class=WebSocketHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
