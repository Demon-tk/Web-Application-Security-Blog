import codecs
import ipaddress
from queue import Queue
import tldextract
from scapy.all import *
from tabulate import tabulate
import time
import get_filterlist

DNS_PACKETS = set()


class DNS_SCHEME:
    # Used to keep DNS data organized
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
    # Used as a thread worker for finding if the first part domain is a tracking domain
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            pkt = self.queue.get()
            try:
                t_regex(pkt, 1)
            finally:
                self.queue.task_done()


class regexWorker(Thread):
    # Used as a thread worker for finding if the CNAME domain is a tracking domain
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            pkt = self.queue.get()
            try:
                t_regex(pkt, 0)
            finally:
                self.queue.task_done()


def delegate_ip(ip):
    """
    Delegates the ip address  to check if it is valid (ipv4 or ipv6)
    :param ip: An ip address
    :return: Bool is the ip address is valid or not
    """
    if check_if_valid_ipv4(ip):
        return True
    if check_if_valid_ipv6(ip):
        return True
    else:
        return False


def check_if_valid_ipv4(pos_ip):
    """
    Checks if ipv4 address is legitimate
    :param pos_ip: A possible ip address
    :return: Bool if the password is working or not
    """
    try:
        ipaddress.IPv4Network(pos_ip)
        return True
    except ValueError:
        return False


def check_if_valid_ipv6(pos_ip):
    """
    Checks if ipv6 address is legitimate
    :param pos_ip: A possible ip address
    :return: Bool if the password is working or not
    """
    try:
        ipaddress.IPv6Network(pos_ip)
        return True
    except ValueError:
        return False


def get_hostname(ip):
    """
    Get the FQDN from an IP
    :param ip: The ip address to scan
    :return: The FQDN name
    """
    try:
        return socket.getfqdn(ip)
    except:
        pass


def summary(pkt):
    """
    Parses the captured packets and places them into DNS_PACKET objects
    :param pkt: The packet to parse
    :return: None
    """
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
                        if delegate_ip(pos_ip):
                            my_scheme.rdata = get_hostname(pos_ip)
                        else:
                            my_scheme.rdata = codecs.decode(pos_ip, 'UTF-8')

                        DNS_PACKETS.add(my_scheme)


def get_domain(hostname):
    """
    Get the domain of a hostname or url
    :param hostname: The hostname to get the domain of
    :return: The domain of the host
    """
    extract = tldextract.extract(str(hostname))
    return extract.domain


def check_cname_cloaking():
    """
    Check if the DNS request may potentially use cloaking to hide tracking
    :return: A set of DNS CNAME request/resonse objects that show different ip or hostname on resolution
    """
    my_local_set = set()
    for pkt in DNS_PACKETS:
        if int(pkt.type) == 5:

            if pkt.rdata is not None:

                src_ip = socket.gethostbyname(pkt.rrname)
                dst_ip = socket.gethostbyname(pkt.rdata)

                src_hn = get_domain(pkt.rrname)
                dst_hn = get_domain(pkt.rdata)
                if src_ip != dst_ip or src_hn != dst_hn:
                    # Cloaking here, check if tracking
                    # print("{} is not the same as {}".format(pkt.rrname, pkt.rdata))
                    my_local_set.add(pkt)
    return my_local_set


def t_regex(pkt, num):
    """
    Scan packets for hosts that are marked as tracking via a modified Adguard list
    :param pkt: The packet to scan
    :param num: To scan the origin or destination host
    :return: None
    """
    if num == 0:
        var = pkt.rdata
    if num == 1:
        var = pkt.rrname

    with open("adguard_regex_bak.txt") as f:
        lines = f.readlines()
    logging.info("Filtering packet {}".format(var))
    for line in lines:
        if line[0] == '!':
            continue
        else:
            if type(var) != str:
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
    """
    Generates the workers for regex checking
    :param pos_c_pkt: The set of packets with DNS objects
    :param num: Check src or dst host
    :return: None
    """
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
    """
    Filter out the results that use CNAME tracking
    :param pos_c_pkt: A set of DNS object packets
    :return: A list of CNAME cloaking trackers
    """
    cname_trackers = set()
    for pkt in pos_c_pkt:
        if not pkt.tracking_tp and pkt.tracking_cname:
            # print(
            #    "{}, tracking: {} -> {}, tracking: ".format(pkt.rrname, pkt.tracking_tp, pkt.rdata, pkt.tracking_cname))
            cname_trackers.add(pkt)
    return cname_trackers


def print_pretty(cname_trackers):
    """
    Prints CNAME clocking trackers pretty
    :param cname_trackers: The set of CNAME trackers
    :return: None
    """
    headers = ["Original subdomain", "DNS Resolved Domain", "Cloaking"]
    data = []
    for domain in cname_trackers:
        data.append([domain.rrname, domain.rdata, domain.tracking_cname])
    print(tabulate(data, headers))


def init():
    """
    Sets up the script to work
    :return: None
    """
    logging.basicConfig(filename='lastrun.log', encoding='utf-8', level=logging.DEBUG)

    o_start = time.time()
    capture = "my_pcap2.pcap"

    one_i = time.time()
    logging.info("Starting to parse packets")
    dns_obj = sniff(offline=capture, prn=summary)
    one_s = time.time()
    logging.info("It took {} to parse the packets".format(one_s - one_i))

    # Update filterlist
    update_i = time.time()
    get_filterlist.init()
    update_s = time.time()
    logging.info("It took {} to update the filterlist".format(update_s - update_i))

    two_i = time.time()
    logging.info("Starting to check for cloaking")
    pos_c_pkt = check_cname_cloaking()
    two_s = time.time()
    logging.info("It took {} to check for cloaking".format(two_s - two_i))

    three_i = time.time()
    logging.info("Starting check for third-party non-cloaking tracking")
    check_tracking(pos_c_pkt, 1)
    three_s = time.time()
    logging.info("It took {} seconds to check for non-cloaking tracking".format(three_s - three_i))

    four_i = time.time()
    logging.info("Starting check for third-party cloaking tracking")
    check_tracking(pos_c_pkt, 0)
    four_s = time.time()
    logging.info("It tookk {} seconds to check for cloaked tracking".format(four_s - four_i))

    logging.info("Done checking for tracking")
    logging.info("Filtering final results")
    cname_trackers = get_results(pos_c_pkt)
    print_pretty(cname_trackers)
    o_stop = time.time()
    logging.info("Done! That took a total of {}".format(o_stop - o_start))


if __name__ == "__main__":
    """We all know what this method does"""
    init()
