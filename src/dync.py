#!/usr/bin/python3
from abc import ABC, abstractmethod
from threading import Thread
import re
import time
import sys


class AddressProvider(ABC):
    def __init__(self, pattern, group=-2):
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.group = group

        if self.group < -2:
            sys.exit(1)

    @abstractmethod
    def get_ip(self):
        pass


class AddressUpdater(ABC):
    def __init__(self, address, domain, user, password, retry):
        self.address = address
        self.domain = domain
        self.user = user
        self.password = password
        self.retry = retry

        if self.retry < -1:
            sys.exit(1)

    @abstractmethod
    def send_ip(self, ip):
        pass


class DynDNSInstance(Thread):
    def __init__(self, iconfig):
        super().__init__(name=iconfig['uid'])
        self.provider = None
        self.updater = None
        self.mode = iconfig['mode']

    def exec(self):
        self.start()

    def run(self):
        current_ip = []
        while True:
            new_ip = self.provider.get_ip()
            if new_ip != current_ip:
                if self.updater.send_ip(new_ip):
                    current_ip = new_ip
                else:
                    sys.exit(1)
            time.sleep(self.mode)
