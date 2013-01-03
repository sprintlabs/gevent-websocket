import sys
import subprocess

import gevent
from gevent import monkey, pywsgi

monkey.patch_all()

try:
    from gevent import subprocess
except ImportError:
    monkey.patch_subprocess()

    import subprocess

import geventwebsocket


def autobahn_echo(environ, start_response):
    websocket = environ.get("wsgi.websocket")

    if not websocket:
        start_response('404 Not Found', [])

        return []

    try:
        while True:
            message = websocket.receive()

            if message is None:
                break

            websocket.send(message)
    except geventwebsocket.WebSocketError:
        pass
    finally:
        websocket.close()


def run_echo_server(address):
    """
    Run an echo websocket server compatible with the fuzzingclient of autobahn.

    :param address: The host/port tuple where to host the echo server.
    """
    server = pywsgi.WSGIServer(
        address, autobahn_echo,
        handler_class=geventwebsocket.WebSocketHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def run_autobahn():
    """
    Spawn the autobahn test suite in a subprocess
    """
    import os.path

    cmd = ['wstest -m fuzzingclient -s %s/autobahn.json' % (
        os.path.dirname(__file__),)]

    wstest = subprocess.Popen(
        cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)

    if wstest.wait():
        # something went wrong, it's boom time.
        print wstest.stderr.read()
        print wstest.stdout.read()

        raise RuntimeError


def waitany(events, timeout=None):
    from gevent.event import AsyncResult

    result = AsyncResult()
    update = result.set

    try:
        for event in events:
            if not event.started:
                event.start()

            if event.ready():
                return event
            else:
                event.rawlink(update)

        return result.get(timeout=timeout)
    finally:
        for event in events:
            event.unlink(update)


if __name__ == '__main__':
    address = ('localhost', 8000)

    echo_thread = gevent.spawn(run_echo_server, address)
    wstest_thread = gevent.spawn(run_autobahn)

    ret = waitany([echo_thread, wstest_thread])

    if ret == wstest_thread:
        # the wstest thread ended first, let's just make sure it was successful
        echo_thread.kill()

        if not wstest_thread.successful():
            raise SystemExit(1)

        sys.exit(0)

    # if we get here then the echo_thread ended first, which is not supposed to
    # happen so die horribly.
    wstest_thread.kill()

    sys.exit(1)
