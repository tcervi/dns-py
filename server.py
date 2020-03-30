import argparse
import datetime
import subprocess
import sys
import socketserver
import threading
import traceback


# Since pip v10, all code has been moved to pip._internal
# precisely in order to make it clear to users that programmatic use of pip is not allowed.
# Using sys.executable to ensure that you will call the same pip associated with the current runtime
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>.")
    print("Installing dnslib now with `pip`:")
    install('dnslib')


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        print("%s - [%s]: Received request from (%s on port %s)" %
              (now, self.__class__.__name__, self.client_address[0], self.client_address[1]))
        try:
            data = self.get_data()
            resp = 'test'
            self.send_data(resp.encode())
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    # self.request[0] - request data (bytes)
    def get_data(self):
        return self.request[0].strip()

    # self.request[1] - request socket
    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Simple DNS implementation in Python.')
    parser.add_argument('--port', default=2053, type=int, help='The server port to listen on.')
    parser.add_argument('--udp', default=True, help='Listen to UDP.')
    parser.add_argument('--tcp', help='Listen to TCP.')

    args = parser.parse_args()

    servers = []
    if args.udp:
        servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp:
        servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for server in servers:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        print("%s server running: [%s]" % (server.RequestHandlerClass.__name__, thread.name))

    try:
        while True:
            time.sleep(30)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()


if __name__ == '__main__':
    main()
