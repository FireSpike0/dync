#!/usr/bin/python3
from abc import ABC, abstractmethod
from threading import Thread
import re
import time
import sys
import yaml
import os
import atexit
import signal
import netifaces as ni
from ipaddress import ip_address, IPv4Address, IPv6Address
from urllib.parse import urlparse
import socket as sck
import select
import requests


class AddressProvider(ABC):
    def __init__(self, pattern, group=-2):
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.group = group

        if self.group < -2:
            sys.exit(1)

    @abstractmethod
    def get_ip(self):
        pass


class InterfaceProvider(AddressProvider):
    def __init__(self, interface, pattern, group=-2):
        super().__init__(pattern, group)
        self.interface = interface

        self.retry = 3
        self.attempt = 0
        self.wait_time = 4

        parse = urlparse(self.interface)
        if parse.netloc == '':
            sys.exit(1)
        self.interface = parse.netloc

        if self.interface not in ni.interfaces():
            sys.exit(1)

    def get_ip(self):
        address_all = ni.ifaddresses(self.interface)
        address_filtered = list()

        if ni.AF_INET in address_all:
            address_filtered.extend(address_all[ni.AF_INET])
        if ni.AF_INET6 in address_all:
            address_filtered.extend(address_all[ni.AF_INET6])

        address_match = list()
        for addr_dict in address_filtered:
            addr = addr_dict['addr']
            if '%' in addr:
                addr = addr.split('%', 1)[0]
            if isinstance(ip_address(addr), IPv6Address):
                addr = ip_address(addr).exploded
            match = re.search(self.pattern, addr)
            if match:
                if self.group == -2:
                    address_match.append(match.string)
                elif self.group == -1:
                    address_match.append(match.group(0))
                else:
                    address_match.append(match.group(self.group))

        if not address_match:
            if self.attempt < self.retry:
                self.attempt += 1
                time.sleep(self.wait_time)
                return self.get_ip()
            sys.exit(1)

        self.attempt = 0
        address_match.sort()
        return address_match


class SocketProvider(AddressProvider):
    def __init__(self, address, pattern, group=-2):
        super().__init__(pattern, group)

        address = address.split('://', 1)[1]
        match = re.search(r':(\d+)(?:\/|)$', address)
        if not match:
            sys.exit(1)
        self.address = address[:-len(match.group(0))].strip('[ ]')
        self.port = int(match.group(1))

        self.retry = 3
        self.attempt = 0
        self.wait_time = 4

        try:
            if not isinstance(ip_address(self.address), (IPv4Address, IPv6Address)):
                sys.exit(1)
        except:
            sys.exit(1)

        if self.port < 0 or self.port > 65535:
            sys.exit(1)

    def get_ip(self):
        if isinstance(ip_address(self.address), IPv4Address):
            addr_family = sck.AF_INET
        elif isinstance(ip_address(self.address), IPv6Address):
            addr_family = sck.AF_INET6

        try:
            s = sck.socket(addr_family, sck.SOCK_DGRAM)
            s.bind(('', self.port))
            s.sendto('ip-request\n'.encode('utf-8'), (self.address, self.port))
            wait = time.monotonic()
            while True:
                if not select.select([s], [], [], self.wait_time)[0]:
                    s.close()
                    if self.attempt < self.retry:
                        self.attempt += 1
                        time.sleep(self.wait_time)
                        return self.get_ip()
                    sys.exit(1)
                data, addr_sender = s.recvfrom(256)
                if ip_address(self.address) == ip_address(addr_sender[0].strip('[ ]')):
                    break
                elif time.monotonic() - wait > self.wait_time:
                    s.close()
                    if self.attempt < self.retry:
                        self.attempt += 1
                        time.sleep(self.wait_time)
                        return self.get_ip()
                    sys.exit(1)
            s.close()
        except OSError:
            if self.attempt < self.retry:
                self.attempt += 1
                time.sleep(self.wait_time)
                return self.get_ip()
            sys.exit(1)

        if not data:
            if self.attempt < self.retry:
                self.attempt += 1
                time.sleep(self.wait_time)
                return self.get_ip()
            sys.exit(1)

        data = re.split(r'[^0-9a-f:\.]+', data.decode('utf-8'), flags=re.IGNORECASE)
        address_filtered = list()
        for addr in data:
            try:
                ip = ip_address(addr)
                if isinstance(ip, IPv4Address):
                    pass
                elif isinstance(ip, IPv6Address):
                    addr = ip.exploded
                else:
                    raise ValueError('\'{}\' does not appear to be an IPv4 or IPv6 address'.format(addr))
            except ValueError:
                pass
            else:
                address_filtered.append(addr)

        address_match = list()
        for addr in address_filtered:
            match = re.search(self.pattern, addr)
            if match:
                if self.group == -2:
                    address_match.append(match.string)
                elif self.group == -1:
                    address_match.append(match.group(0))
                else:
                    address_match.append(match.group(self.group))

        if not address_match:
            if self.attempt < self.retry:
                self.attempt += 1
                time.sleep(self.wait_time)
                return self.get_ip()
            sys.exit(1)

        self.attempt = 0
        address_match.sort()
        return address_match


class WebProvider(AddressProvider):
    def __init__(self, url, pattern, group=-2):
        super().__init__(pattern, group)
        self.url = url

        self.retry = 3
        self.attempt = 0
        self.wait_time = 4

        if urlparse(self.url).netloc == '':
            sys.exit(1)

    def get_ip(self):
        try:
            r = requests.get(self.url)
            if r.status_code == 200:
                data = re.split(r'[^0-9a-f:\.]+', r.text, flags=re.IGNORECASE)
                address_filtered = list()
                for addr in data:
                    try:
                        ip = ip_address(addr)
                        if isinstance(ip, IPv4Address):
                            pass
                        elif isinstance(ip, IPv6Address):
                            addr = ip.exploded
                        else:
                            raise ValueError('\'{}\' does not appear to be an IPv4 or IPv6 address'.format(addr))
                    except ValueError:
                        pass
                    else:
                        address_filtered.append(addr)

                address_match = list()
                for addr in address_filtered:
                    match = re.search(self.pattern, addr)
                    if match:
                        if self.group == -2:
                            address_match.append(match.string)
                        elif self.group == -1:
                            address_match.append(match.group(0))
                        else:
                            address_match.append(match.group(self.group))

                if not address_match:
                    if self.attempt < self.retry:
                        self.attempt += 1
                        time.sleep(self.wait_time)
                        return self.get_ip()
                    sys.exit(1)

                self.attempt = 0
                address_match.sort()
                return address_match
            else:
                if self.attempt < self.retry:
                    self.attempt += 1
                    time.sleep(self.wait_time)
                    return self.get_ip()
                sys.exit(1)
        except:
            if self.attempt < self.retry:
                self.attempt += 1
                time.sleep(self.wait_time)
                return self.get_ip()
            sys.exit(1)


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


class DynDNS2Updater(AddressUpdater):
    def __init__(self, address, domain, user, password, retry):
        super().__init__(address, domain, user, password, retry)
        self.ua = '{c:} - {n:} - {v:}'.format(c='FireSpike0', n=dyncBase.NAME, v=dyncBase.VERSION)

        self.attempt = 0
        self.wait_time = 1800

        if not isinstance(self.domain, list):
            self.domain = list(map(str.strip, self.domain.split(',')))

        if len(self.domain) < 1 or len(self.domain) > 20:
            sys.exit(1)

        parse = urlparse(self.address)
        if parse.scheme.lower() not in ['http', 'https'] or parse.netloc == '':
            sys.exit(1)

    def send_ip(self, ip):
        try:
            r = requests.get(
                self.address,
                headers={
                    'User-Agent': self.ua
                },
                auth=requests.auth.HTTPBasicAuth(self.user, self.password),
                params={
                    'hostname': ','.join(self.domain),
                    'myip': ','.join(ip)
                }
            )
        except:
            if self.retry == -1 or (self.retry != -1 and self.attempt < self.retry):
                self.attempt += 1
                time.sleep(self.wait_time / 10)
                return self.send_ip(ip)
            return False

        update_result = list()
        domain_index = 0
        for line in r.text.split('\n'):
            line = line.strip()
            if line == '':
                continue
            elif line.startswith('good') and (not line.endswith('127.0.0.1') or ','.join(ip) == '127.0.0.1'):
                update_result.append(True)
                domain_index += 1
            elif line.startswith('nochg'):
                update_result.append(True)
                domain_index += 1
            elif line.startswith('notfqdn') and len(self.domain) >= 1:
                update_result.append(False)
                domain_index += 1
            elif line.startswith('notfqdn') and len(self.domain) < 1:
                update_result.append(False)
            elif line.startswith('nohost'):
                update_result.append(False)
                domain_index += 1
            elif line.startswith('numhost'):
                update_result.append(False)
                domain_index += 1
            elif line.startswith('abuse'):
                update_result.append(False)
                domain_index += 1
            elif line.startswith('good 127.0.0.1') and ','.join(ip) != '127.0.0.1':
                update_result.append(False)
                domain_index += 1
            elif line.startswith('badagent'):
                update_result.append(False)
            elif line.startswith('badauth'):
                update_result.append(False)
            elif line.startswith('badsys'):
                update_result.append(False)
            elif line.startswith('!donator'):
                update_result.append(False)
            elif line.startswith('dnserr'):
                if self.retry == -1 or (self.retry != -1 and self.attempt < self.retry):
                    self.attempt += 1
                    time.sleep(self.wait_time)
                    return self.send_ip(ip)
                update_result.append(False)
            elif line.startswith('911'):
                if self.retry == -1 or (self.retry != -1 and self.attempt < self.retry):
                    self.attempt += 1
                    time.sleep(self.wait_time)
                    return self.send_ip(ip)
                update_result.append(False)
            else:
                update_result.append(False)

        return all(update_result)


class DynDNSInstance(Thread):
    def __init__(self, iconfig):
        super().__init__(name=iconfig['uid'])

        self.provider = None
        sect = iconfig['ip']
        if sect['origin'].startswith('iface://'):
            self.provider = InterfaceProvider(sect['origin'], sect['pattern'], sect['group'])
        elif sect['origin'].startswith('sock://'):
            self.provider = SocketProvider(sect['origin'], sect['pattern'], sect['group'])
        elif sect['origin'].startswith('http://') or sect['origin'].startswith('https://'):
            self.provider = WebProvider(sect['origin'], sect['pattern'], sect['group'])
        else:
            sys.exit(1)

        self.updater = None
        sect = iconfig['server']
        if sect['protocol'].strip().lower() == 'dyndns2':
            self.updater = DynDNS2Updater(sect['address'], sect['domain'], sect['user'], sect['password'], sect['retry'])
        else:
            sys.exit(1)

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


class dyncBase(ABC):
    NAME = 'dync'
    VERSION = '0.0.0'
    def __init__(self, configfile):
        self.config = yaml.load(open(configfile, mode='r', encoding='utf-8'), Loader=yaml.FullLoader)
        self.instances = list()

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def stop(self):
        pass

    @abstractmethod
    def restart(self):
        pass

    def run(self):
        for instance in self.config['instance']:
            self.instances.append(DynDNSInstance(instance))
            self.instances[-1].exec()
        for instance in self.instances:
            instance.join()
        self.stop()


class dyncApp(dyncBase):
    def __init__(self, configfile):
        super().__init__(configfile)

    def start(self):
        self.run()

    def stop(self):
        return

    def restart(self):
        return


# basic daemon, see
#   https://web.archive.org/web/20200611115733/https://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python//
# for details & credit
class dyncDaemon(dyncBase):
    def __init__(self, configfile, pidfile):
        super().__init__(configfile)
        self.pidfile = pidfile

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            sys.exit(1)

        os.chdir('/')
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            sys.exit(1)

        sys.stdout.flush()
        sys.stderr.flush()
        stdin = open(os.devnull, 'r')
        stdout = open(os.devnull, 'a+')
        stderr = open(os.devnull, 'a+')

        os.dup2(stdin.fileno(), sys.stdin.fileno())
        os.dup2(stdout.fileno(), sys.stdout.fileno())
        os.dup2(stderr.fileno(), sys.stderr.fileno())

        atexit.register(self.delpid)

        pid = str(os.getpid())
        with open(self.pidfile, 'w+') as f:
            f.write(pid + '\n')

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        try:
            with open(self.pidfile, 'r') as f:
                pid = int(f.read().strip())
        except IOError:
            pid = None

        if pid:
            sys.exit(1)

        self.daemonize()
        self.run()

    def stop(self):
        try:
            with open(self.pidfile, 'r') as f:
                pid = int(f.read().strip())
        except IOError:
            pid = None

        if not pid:
            return

        if pid == os.getpid():
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)

        try:
            while True:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            if str(err.args).find('No such process') > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()
