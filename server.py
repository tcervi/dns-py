import argparse
import datetime
from multiprocessing import Process
import pickle
import re
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


class DNSResourceRecord:
    domain_name: string
    record_class: CLASS
    record_type: QTYPE
    ttl: int
    data: string

    def __init__(self, domain_name, record_class, record_type, data, ttl=300):
        self.domain_name = domain_name
        self.record_type = record_type
        self.record_class = record_class
        self.ttl = ttl
        self.data = data


def domain_registration():
    sys.stdin = open(0)
    while True:
        try:
            os.system('clear')
            print("You can register new domains typing it in a single line ")
            print("separating fields with whitespaces:  domain_name domain_class domain_type address/info")
            print("Example: www.google.com IN A 1.2.3.4")
            domain_entry = prompt('>>>> Enter domain: ')
        except KeyboardInterrupt:
            continue
        except EOFError:
            break
        else:
            now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            registration_result = handle_domain_registration(domain_entry)
            if registration_result:
                print('[%s] - You entered new domain: [%s]' % (now, domain_entry))
            else:
                print('[%s] - You entered an invalid domain: [%s]' % (now, domain_entry))
            time.sleep(3)
    print('Finished domain registration interface.')
    print('So long, and thanks for all the fish!')


def check_domain_entry(domain_name, domain_class, domain_type):
    result_entry = []
    resource_records = pickle.load(open("records.p", "rb"))
    for name, record in resource_records:
        if name != str(domain_name)[:-1] and name != str(domain_name):
            continue
        if isinstance(record, DNSResourceRecord) \
                and (record.domain_name == str(domain_name)[:-1] or record.domain_name == str(domain_name)) \
                and record.record_class == domain_class:
            result_entry.append(record)
            if record.record_type != domain_type:
                next_entries = check_domain_entry(record.data, domain_class, domain_type)
                for entry in next_entries:
                    result_entry.append(entry)
            break
    return result_entry


def get_data_by_type(record_type, data):
    if record_type == QTYPE[1] and validate_domain_data(QTYPE[1], data):
        return 1, A(data)
    elif record_type == QTYPE[5] and validate_domain_data(QTYPE[5], data):
        return 5, CNAME(data)
    elif record_type == QTYPE[16] and validate_domain_data(QTYPE[16], data):
        return 16, TXT(data)
    elif record_type == QTYPE[28] and validate_domain_data(QTYPE[28], data):
        return 28, AAAA(data)
    else:
        return None


def handle_domain_entries(request, entries):
    # handling reply message for record not found
    if len(entries) == 0:
        answer = DNSRecord(DNSHeader(id=request.header.id, rcode=RCODE.NXDOMAIN, qr=1, ra=1), q=request.q)
        return answer.pack()

    # handling successful message for record found
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
    domain_entries = check_domain_entry(question.qname, CLASS[question.qclass], QTYPE[question.qtype])
    return handle_domain_entries(request, domain_entries)


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

    # TODO update registration of already existing domain names
    domain_dic = validate_new_domain(data_str)
    if domain_dic is None:
        print("FAILED to validate: [%s]" % data_str)
        return False

    new_record = DNSResourceRecord(domain_dic['domain_name'], domain_dic['class'],
                                   domain_dic['qtype'], domain_dic['data'], domain_dic['ttl'])
    if new_record is not None:
        resource_records.append([new_record.domain_name, new_record])
        print("Registered domain: [%s %s %s %s]" %
              (new_record.domain_name, new_record.record_class, new_record.record_type, new_record.data))
        pickle.dump(resource_records, open("records.p", "wb"))
    else:
        print("FAILED to create new record: [%s]" % domain_dic)
        return False
    return True


def validate_new_domain(data_str):
    # registration string like "www.google.com IN A 1.2.3.4"
    if not isinstance(data_str, str):
        return None

    registration = data_str.split()
    if len(registration) != 4:
        return None

    new_domain_name = validate_domain_name(registration[0])
    if new_domain_name is None:
        return None

    new_domain_class = validate_domain_class(registration[1])
    if new_domain_class is None:
        return None

    new_domain_type = validate_domain_type(registration[2])
    if new_domain_type is None:
        return None

    new_domain_data = validate_domain_data(new_domain_type, registration[3])
    if new_domain_data is None:
        return None

    domain_dic = {'domain_name': new_domain_name, 'class': new_domain_class,
                  'qtype': new_domain_type, 'data': new_domain_data, 'ttl': 3600}
    return domain_dic


def validate_domain_name(domain_name):
    # For sequences, (strings, lists, tuples), use the fact that empty sequences are false.
    if not domain_name:
        return None
    # RFC1035: names - 255 octets or less
    if len(domain_name) > 255:
        return None
    # RFC1035: labels - 63 octets or less
    labels = domain_name.split('.')
    for domain_label in labels:
        if len(domain_label) > 63:
            return None
    # RFC1035: must start with a letter, end with a letter or digit,
    # and have as interior characters only letters, digits, and hyphen
    if not re.match(r"^[a-zA-Z]", domain_name) or not re.match(r".*[a-zA-Z.]$", domain_name):
        return None
    if re.match(r".*[^\w\.\-]", domain_name):
        return None
    return domain_name


def validate_domain_class(domain_class):
    # CLASS =  Bimap('CLASS', {1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'},DNSError)
    if domain_class != CLASS[1] and domain_class != CLASS[2] and domain_class != CLASS[3] and \
            domain_class != CLASS[4] and domain_class != CLASS[254] and domain_class != CLASS[255]:
        return None
    else:
        return domain_class


def validate_domain_type(domain_type):
    # TYPE = Bimap('QTYPE', {1:'A',..., 5:'CNAME',..., 16:'TXT',..., 28:'AAAA',...}, DNSError)
    if domain_type != QTYPE[1] and domain_type != QTYPE[5] and \
            domain_type != QTYPE[16] and domain_type != QTYPE[28]:
        return None
    else:
        return domain_type


def validate_domain_data(domain_type, domain_data):
    # TYPE            value and meaning [RFC1035]
    if domain_data is None or \
            not isinstance(domain_type, str) or not isinstance(domain_data, str):
        return None
    # A               1 a host address (x.y.z.w)
    if domain_type == QTYPE[1] and \
            not re.match(r"^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$", domain_data):
        return None
    # AAAA            1 a host address (A:B:C:D:E:F:G:H) [RFC3596]
    if domain_type == QTYPE[28] and \
            not re.match(
                r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,"
                r"6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,"
                r"4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,"
                r"2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,"
                r"7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2["
                r"0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,"
                r"4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",
                domain_data):
        return None
    # CNAME           5 the canonical name for an alias
    if domain_type == QTYPE[5] and validate_domain_name(domain_data) is None:
        return None
    # TXT             16 text strings
    # [RFC1464] The format consists of the attribute name followed by the value of the attribute.
    # The name and value are separated by an equals sign (=)
    # Any printable ASCII character is permitted for the attribute name.
    # All printable ASCII characters are permitted in the attribute value
    if domain_type == QTYPE[16] and not re.match(r".*[=]", domain_data):
        return None
    return domain_data


def main():
    parser = argparse.ArgumentParser(description='Simple DNS implementation in Python.')
    parser.add_argument('--request_port', default=2053, type=int, help='The server port to listen for DNS Clients.')
    parser.add_argument('--register_port', default=2063, type=int, help='The server port to listen for registrations.')
    parser.add_argument('--udp', default=True, help='Listen to UDP.')
    parser.add_argument('--tcp', help='Listen to TCP.')
    args = parser.parse_args()

    # starting servers with respective sockets handling
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

    # starting server with one fake entry (first run)
    # not mandatory, can be removed later
    resource_records = pickle.load(open("records.p", "rb"))
    if len(resource_records) == 0:
        record = DNSResourceRecord("www.google.com", "A", "IN", "1.2.3.4", 3600)
        dns_resource_records = [[record.domain_name, record]]
        pickle.dump(dns_resource_records, open("records.p", "wb"))

    # starting cli process for registration
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
