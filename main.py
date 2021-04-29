from scapy.all import *
from urllib.parse import urlparse
import tldextract
import codecs
import socket
import ipaddress
import re
from threading import Thread
from queue import Queue
import logging

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
        self.tracking_cname = False
        self.tracking_tp = False


class regexLifter(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        pkt = self.queue.get()
        try:
            t_regex(pkt, 1)
        finally:
            self.queue.task_done()


class regexWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        pkt = self.queue.get()
        try:
            t_regex(pkt, 0)
        finally:
            self.queue.task_done()


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

                src_hn = get_domain(pkt.rrname)
                dst_hn = get_domain(pkt.rdata)
                """print("{} -> {}".format(pkt.rrname, pkt.rdata))
                print("{} -> {}".format(src_ip, dst_ip))
                print("{} -> {}".format(src_hn, dst_hn))
                print("##########################################################################")"""
                if src_ip != dst_ip or src_hn != dst_hn:
                    # Cloaking here, check if tracking
                    # print("{} is not the same as {}".format(pkt.rrname, pkt.rdata))
                    my_local_set.add(pkt)
    return my_local_set


def t_regex(pkt, num):
    if num == 0:
        var = pkt.rdata
    if num == 1:
        var = pkt.rrname

    with open("adguard_regex.txt") as f:
        lines = f.readlines()
    logging.info("Filtering packet {}".format(var))
    for line in lines:
        if line[0] == '!':
            continue
        else:
            if type(pkt.rdata) != str:
                var = codecs.decode(var, 'UTF-8')
            test = re.search(line.strip(), var)
            if test:
                logging.info("Found tracking match for {}".format(var))
                if num == 1:
                    pkt.tracking_tp = True
                if num == 0:
                    pkt.tracking_cname = True
                break
    logging.info("Done with {}".format(pkt.id))


def check_tracking(pos_c_pkt, num):
    queue = Queue()
    for x in range(200):
        if num == 0:
            worker = regexWorker(queue)
        if num == 1:
            worker = regexLifter(queue)
        worker.daemon = True
        worker.start()
    for pkt in pos_c_pkt:
        logging.info("Queueing {}".format(pkt.id))
        queue.put(pkt)
    queue.join()
    logging.info("Done")


def get_results(pos_c_pkt):
    cname_trackers = set()
    for pkt in pos_c_pkt:
        if not pkt.tracking_tp and pkt.tracking_cname:
            print(
                "{}, tracking: {} -> {}, tracking: ".format(pkt.rrname, pkt.tracking_tp, pkt.rdata, pkt.tracking_cname))
            cname_trackers.add(pkt)
    return cname_trackers


def print_pretty(cname_trackers):
    print("Original subdomain             |              DNS Resolved Domain                       | Cloaking")
    print("===============================|========================================================|=========")
    for domain in cname_trackers:
        print("{}           |              {}             | {}".format(domain.rrname, domain.rdata,
                                                                         domain.tracking_cname))


def init():
    capture = "my_pcap2.pcap"
    logging.info("Starting to parse packets")
    dns_obj = sniff(offline=capture, prn=summary)
    logging.info("Starting to check for cloaking")
    pos_c_pkt = check_cname_cloaking()
    logging.info("Starting check for third-part non-cloaking tracking")
    check_tracking(pos_c_pkt, 1)
    logging.info("Starting check for third-part cloaking tracking")
    check_tracking(pos_c_pkt, 0)
    logging.info("Done checking for tracking")
    logging.info("Filtering final results")
    cname_trackers = get_results(pos_c_pkt)
    print_pretty(cname_trackers)


def main():
    init()


main()
