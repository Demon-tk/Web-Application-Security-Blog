from scapy.all import *
from urllib.parse import urlparse
import tldextract
import codecs
import socket
import ipaddress
import re

DNS_PACKETS = set()


class DNS_SCHEME:
    # {'rrname': b'smetrics.redhat.com.', 'type': 5, 'rclass': 1, 'ttl': 2087, 'rdlen': None, 'rdata': b'redhat.com.ssl.sc.omtrdc.net.'}
    def __init__(self, id):
        self.id = id
        self.rrname = None
        self.type = None
        self.rclass = None
        self.ttl = None
        self.rdlen = None
        self.rdata = None
        self.tracking = False


capture = "my_pcap2.pcap"


def delegate_ip(ip):
    if check_if_valid_ipv4(ip):
        return True
    if check_if_valid_ipv6(ip):
        return True
    else:
        return False


def check_if_valid_ipv4(pos_ip):
    try:
        ipaddress.IPv4Network(pos_ip)
        return True
    except ValueError:
        return False


def check_if_valid_ipv6(pos_ip):
    try:
        ipaddress.IPv6Network(pos_ip)
        return True
    except ValueError:
        return False


def get_hostname(ip):
    try:
        return socket.getfqdn(ip)
    except:
        pass


def summary(pkt):
    # an_records_objects = set()
    count = len(DNS_PACKETS)
    if UDP in pkt:
        # UDP info
        udp_sport = pkt[UDP].sport
        udp_dport = pkt[UDP].dport

        if int(udp_sport) == 53 or int(udp_dport == 53):
            dns_scheme = pkt[DNS]

            an_record = dns_scheme.an

            # print(dns_scheme.answers)

            if an_record is not None:
                an_fields = an_record.fields

                # print("###############################")
                # print(an_fields)
                # print("\n")
                if an_fields is not None:
                    my_scheme = DNS_SCHEME(count)
                    my_scheme.rrname = codecs.decode(an_fields.get("rrname"), 'UTF-8')
                    my_scheme.type = an_fields.get("type")
                    my_scheme.rclass = an_fields.get("rclass")
                    my_scheme.ttl = an_fields.get("ttl")
                    my_scheme.rdlen = an_fields.get("rlen")

                    # Check ip or hostname or none
                    pos_ip = an_fields.get("rdata")
                    if pos_ip is not None:
                        if delegate_ip(pos_ip):
                            my_scheme.rdata = get_hostname(pos_ip)
                        else:
                            my_scheme.rdata = codecs.decode(pos_ip, 'UTF-8')
                        # print("Added packet  " + str(count))
                        DNS_PACKETS.add(my_scheme)


def get_domain(hostname):
    extract = tldextract.extract(str(hostname))
    return extract.domain


def check_cname_cloaking():
    my_local_set = set()
    for pkt in DNS_PACKETS:
        if int(pkt.type) == 5:

            if pkt.rdata is not None:

                src_ip = socket.gethostbyname(pkt.rrname)
                dst_ip = socket.gethostbyname(pkt.rdata)

                if src_ip != dst_ip:
                    # Cloaking here, check if tracking
                    print("{} is not the same as {}".format(pkt.rrname, pkt.rdata))
                    my_local_set.add(pkt)
    return my_local_set


def t_regex(pkt):
    with open("adguard_regex") as f:
        line = f.readline()
        if line[0] != '!':
            test = re.search(line.strip(), pkt.rdata)
            if test:
                pkt.tracking = True


def check_tracking(pos_c_pkt):
    for pkt in pos_c_pkt:
        pass


def init():
    dns_obj = sniff(offline=capture, prn=summary)
    pos_c_pkt = check_cname_cloaking()
    check_tracking(pos_c_pkt)


def main():
    init()


main()
