import logging
from threading import Thread
import requests
import os
import codecs
import regex as re
from queue import Queue

mySet = set()


class TO_CHANGE():
    def __init__(self, init):
        self.init = init
        self.form = ''

    def set_form(self, form):
        self.form = form


class Worker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            line = self.queue.get()
            try:
                regexer(line)
            finally:
                self.queue.task_done()


def regexer(line):
    line = line.strip()
    # skip if it is commented out or negated
    if line[0].strip() == "!" or line[:2].strip == '@@':
        pass
    else:
        # make the link object
        myLine = TO_CHANGE(line)

        # Remove all chars after a $
        line = re.sub(r'[^\$]*$', r'', line)
        # Removes all $
        line = re.sub(r'[\$]', r'', line)
        # Remove all chars after ## or @@
        line = re.sub(r'#|@{}', r'', line)
        # Replace * with .
        line = re.sub(r'[*]', r'.', line)
        # Replaces . with \.
        line = re.sub(r'[\.]', r'\\.', line)
        # Replaces ^ with  any character, but a letter, a digit, or one of the following: _ - . %
        # line = re.sub(r'[\^]', r'[/$[\d\_\-\.\%]||[a-z]', line)
        # I think its best to just replace it with nothing
        line = re.sub(r'[\^]', r'', line)
        # Replaces || with ^
        line = re.sub(r'^[|]{2}', r'^', line)

        myLine.set_form(line)
        mySet.add(myLine)
    # Add that line to the new file


def download_filterlist():
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt")
        os.path.join(os.getcwd(), 'adguard_default.txt')
        f = open('adguard_default.txt', 'w')
        f.write(codecs.decode(r.content, 'utf-8'))
    except:
        logging.WARN("Unable to update filterlist, using local version")


def convert_to_regex():
    with open('adguard_default.txt', 'r') as base:
        lines = base.readlines()
    # threading here
    queue = Queue()
    for x in range(500):
        worker = Worker(queue)
        worker.daemon = True
        worker.start()

    for line in lines:
        queue.put(line)
    queue.join()


def make_new():
    with open('adguard_regex.txt', 'w') as f:
        for myLine in mySet:
            form = myLine.form
            if len(form) > 1:
                f.write(form)
                f.write("\n")


def init():
    download_filterlist()
    convert_to_regex()
    make_new()


if __name__ == "__main__":
    init()
