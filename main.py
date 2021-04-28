from scapy.all import *
from urllib.parse import urlparse
import tldextract
import codecs
import socket
import ipaddress

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


capture = "my_pcap2.pcap"


def check_if_valid_ip(pos_ip):
    try:
        ipaddress.IPv4Network(pos_ip)
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
            if an_record is not None:
                an_fields = an_record.fields
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
                        if check_if_valid_ip(pos_ip):
                            my_scheme.rdata = get_hostname(pos_ip)
                    # print("Added packet  " + str(count))
                    DNS_PACKETS.add(my_scheme)


def get_domain(hostname):
    extract = tldextract.extract(str(hostname))
    return extract.domain


def check_cname_cloaking():
    for pkt in DNS_PACKETS:
        if int(pkt.type) == 5:
            src_hostname = get_hostname(pkt.rrname)
            dst_hostname = get_hostname(pkt.rdata)

            if dst_hostname is not None:
                if src_hostname != dst_hostname:
                    # Cloaking here, check if tracking
                    print("{} is not the same as {}".format(src_hostname, dst_hostname))


def init():
    dns_obj = sniff(offline=capture, prn=summary)
    check_cname_cloaking()


def main():
    init()


main()
