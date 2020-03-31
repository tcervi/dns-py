import argparse
import datetime
from multiprocessing import Process
import pickle
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
try:
    from prompt_toolkit import prompt
except ImportError:
    print("Missing dependency prompt_toolkit: <https://python-prompt-toolkit.readthedocs.io/en/stable/index.html>.")
    print("Installing prompt_toolkit now with `pip`:")
    install('prompt_toolkit')


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


def domain_registration():
    sys.stdin = open(0)
    while True:
        try:
            domain_entry = prompt('> Enter domain: ')
        except KeyboardInterrupt:
            continue
        except EOFError:
            break
        else:
            print('You entered: [%s]' % domain_entry)
            handle_domain_registration(domain_entry)
    print('GoodBye!')


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


def check_domain_entry(domain_name, domain_class):
    result_entry = []
    resource_records = pickle.load(open("records.p", "rb"))
    for name, record in resource_records:
        if name != str(domain_name)[:-1]:
            continue
        # TODO Handle CNAME sequence
        if isinstance(record, DNSResourceRecord) \
                and record.domain_name == str(domain_name)[:-1] \
                and record.record_class == domain_class:
            result_entry.append(record)
    return result_entry


def get_data_by_type(record_type, data):
    if record_type == QTYPE[1]:
        return 1, A(data)
    elif record_type == QTYPE[5]:
        return 5, CNAME(data)
    elif record_type == QTYPE[16]:
        return 16, TXT(data)
    elif record_type == QTYPE[28]:
        return 28, AAAA(data)
    else:
        return None


def handle_domain_entries(request, entries):
    answer = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    for entry in entries:
        data = get_data_by_type(entry.record_type, entry.data)
        if data is None:
            continue
        answer.add_answer(RR(entry.domain_name, data[0], ttl=entry.ttl, rdata=data[1]))
    # answer.add_auth(RR())
    # answer.add_ar(RR())
    return answer.pack()


def db_lookup(request):
    question = request.q
    domain_entries = check_domain_entry(question.qname, CLASS[question.qclass])
    if len(domain_entries) != 0:
        return handle_domain_entries(request, domain_entries)
    else:
        # TODO Handle error
        return None


def handle_dns_client(data):
    request = DNSRecord.parse(data)
    questions_number = len(request.questions)
    questions_answers = []
    for i in range(questions_number):
        packed_answer = db_lookup(request)
        questions_answers.append(packed_answer)
    return questions_answers


def handle_domain_registration(data_str):
    resource_records = pickle.load(open("records.p", "rb"))
    # TODO validation rules
    registration = data_str.split()
    if len(registration) != 4:
        return
    # registration string like "www.google.com IN A 1.2.3.4"
    new_record = DNSResourceRecord(registration[0], registration[2], registration[1], registration[3], 3600)
    if new_record is not None:
        resource_records.append([new_record.domain_name, new_record])
        print("Registered domain: [%s %s %s %s]" %
              (new_record.domain_name, new_record.record_class, new_record.record_type, new_record.data))
    pickle.dump(resource_records, open("records.p", "wb"))


def main():
    parser = argparse.ArgumentParser(description='Simple DNS implementation in Python.')
    parser.add_argument('--request_port', default=2053, type=int, help='The server port to listen for DNS Clients.')
    parser.add_argument('--register_port', default=2063, type=int, help='The server port to listen for registrations.')
    parser.add_argument('--udp', default=True, help='Listen to UDP.')
    parser.add_argument('--tcp', help='Listen to TCP.')
    args = parser.parse_args()

    record = DNSResourceRecord("www.google.com", "A", "IN", "1.2.3.4", 3600)
    dns_resource_records = [[record.domain_name, record]]
    pickle.dump(dns_resource_records, open("records.p", "wb"))

    servers = []
    if args.udp:
        servers.append(socketserver.ThreadingUDPServer(('', args.request_port), UDPRequestHandler))
    if args.tcp:
        servers.append(socketserver.ThreadingTCPServer(('', args.request_port), TCPRequestHandler))

    for server in servers:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        print("%s server running: [%s]" % (server.RequestHandlerClass.__name__, thread.name))

    registration_process = Process(target=domain_registration)
    registration_process.start()
    registration_process.join()

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
