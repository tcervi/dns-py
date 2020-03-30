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
            if is_registration_request(data):
                handle_domain_registration(data)
            else:
                response_packets = handle_dns_client(data)
                for resp_packet in response_packets:
                    self.send_data(resp_packet)
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


class DNSResourceRecord:
    domain_name: string
    record_type: QTYPE
    record_class: CLASS
    ttl: int
    data: string

    def __init__(self, domain_name, record_type, record_class, data, ttl=300):
        self.domain_name = domain_name
        self.record_type = record_type
        self.record_class = record_class
        self.ttl = ttl
        self.data = data


dns_resource_records = []


def is_registration_request(data):
    try:
        request = DNSRecord.parse(data)
        return False
    except Exception:
        return True


def db_lookup(request):
    question = request.q
    if question.qname == "www.google.com" and question.qtype == QTYPE.A and question.qclass == CLASS.IN:
        answer = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        answer.add_answer(RR("www.google.com", QTYPE.A, ttl=60, rdata=A("1.2.3.4")))
        # answer.add_auth(RR())
        # answer.add_ar(RR())
        return answer.pack()


def handle_dns_client(data):
    request = DNSRecord.parse(data)
    questions_number = len(request.questions)
    questions_answers = []
    for i in range(questions_number):
        packed_answer = db_lookup(request)
        questions_answers.append(packed_answer)
    return questions_answers


def handle_domain_registration(data):
    print("Starting domain registration: %s" % data)
    data_str = data.decode('utf-8')
    registration = data_str.split()
    if len(registration) != 4:
        return
    new_record = DNSResourceRecord(registration[0], registration[1], registration[2], registration[3], 3600)
    if new_record is not None:
        dns_resource_records.append(new_record)
        print("Registered domain: [%s,%s,%s,%s]" %
          (new_record.domain_name, new_record.record_type, new_record.record_class, new_record.data))


def main():
    parser = argparse.ArgumentParser(description='Simple DNS implementation in Python.')
    parser.add_argument('--request_port', default=2053, type=int, help='The server port to listen for DNS Clients.')
    parser.add_argument('--register_port', default=2063, type=int, help='The server port to listen for registrations.')
    parser.add_argument('--udp', default=True, help='Listen to UDP.')
    parser.add_argument('--tcp', help='Listen to TCP.')

    args = parser.parse_args()

    servers = []
    if args.udp:
        servers.append(socketserver.ThreadingUDPServer(('', args.request_port), UDPRequestHandler))
        servers.append(socketserver.ThreadingUDPServer(('', args.register_port), UDPRequestHandler))
    if args.tcp:
        servers.append(socketserver.ThreadingTCPServer(('', args.request_port), TCPRequestHandler))

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
