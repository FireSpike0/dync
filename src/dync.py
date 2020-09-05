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
import platform
from argparse import ArgumentParser
import logging


class LogMessage():
    LOADING_CONFIGURATION = 'Loading configuration from \'%s\'.'
    STARTING = 'Starting in %s mode.'
    STOPPING = 'Stopping.'
    RESTARTING = 'Restarting.'

    LAUNCH_CRITICAL_STARTING = 'The daemon is already running (PID: %d).'
    LAUNCH_CRITICAL_FORKING = 'Forking process failed.'
    HALT_CRITICAL_STOPPING = 'Stopping the daemon failed.'

    INITIALIZING_INSTANCE = 'Initializing instance \'%s\'.'
    STARTING_INSTANCE = 'Starting instance \'%s\'.'

    INITIALIZING_COMPONENT = 'Initializing %s (%s).'
    EXECUTING_PROVIDER = 'Fetching IP address (%s).'
    EXECUTING_UPDATER = 'Updating IP address to \'%s\'.'

    INVALID_CONFIG_GROUP = 'The group value \'%d\' is invalid.'
    INVALID_CONFIG_PROVIDER_TYPE = 'The address provider \'%s\' is unknown.'
    INVALID_CONFIG_PROVIDER_URL = 'The address provider URL is invalid: %s.'
    INVALID_CONFIG_UPDATER_TYPE = 'The address updater \'%s\' is unknown.'
    INVALID_CONFIG_UPDATER_URL = 'The address updater URL is invalid: %s.'
    INVALID_CONFIG_UPDATER_RETRY = 'The retry value \'%d\' is invalid.'
    INVALID_CONFIG_UPDATER_UNSPECIFIED = '%s'

    RUNTIME_INFO_UPDATER_PROTOCOL_MESSAGE = '%s'
    RUNTIME_WARNING_UPDATER_PROTOCOL_MESSAGE = '%s'
    RUNTIME_ERROR_PROVIDER_ADDRESS = 'No addresses were %s during attempt #%d of #%d.'
    RUNTIME_ERROR_UPDATER_SENDING = 'Sending IP address failed during attempt #%d of #%d.'
    RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE = '%s'

    @staticmethod
    def convert_args(args):
        if 'self' in args:
            args.pop('self')

        return ', '.join(['{:}: \'{:}\''.format(key, args[key]) for key in args])


class AddressProvider(ABC):
    def __init__(self, pattern, group=-2):
        logging.debug(LogMessage.INITIALIZING_COMPONENT, type(self).__name__, LogMessage.convert_args(locals()))

        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.group = group

        if self.group < -2:
            logging.critical(LogMessage.INVALID_CONFIG_GROUP, self.group)
            sys.exit(1)

    @abstractmethod
    def get_ip(self):
        pass


class InterfaceProvider(AddressProvider):
    def __init__(self, interface, pattern, group=-2):
        logging.debug(LogMessage.INITIALIZING_COMPONENT, type(self).__name__, LogMessage.convert_args(locals()))

        super().__init__(pattern, group)
        self.interface = interface

        self.retry = 3
        self.attempt = 0
        self.wait_time = 4

        parse = urlparse(self.interface)
        if parse.netloc == '':
            logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_URL, 'No location')
            sys.exit(1)
        self.interface = parse.netloc

        if self.interface not in ni.interfaces():
            logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_URL, 'Not exist')
            sys.exit(1)

    def get_ip(self):
        logging.info(LogMessage.EXECUTING_PROVIDER, 'iface')

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
            logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'matched', self.attempt + 1, self.retry + 1)
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
        logging.debug(LogMessage.INITIALIZING_COMPONENT, type(self).__name__, LogMessage.convert_args(locals()))

        super().__init__(pattern, group)

        address = address.split('://', 1)[1]
        match = re.search(r':(\d+)(?:\/|)$', address)
        if not match:
            logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_URL, 'No port')
            sys.exit(1)
        self.address = address[:-len(match.group(0))].strip('[ ]')
        self.port = int(match.group(1))

        self.retry = 3
        self.attempt = 0
        self.wait_time = 4

        try:
            if not isinstance(ip_address(self.address), (IPv4Address, IPv6Address)):
                logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_URL, 'Not IPv4 or IPv6 address')
                sys.exit(1)
        except:
            logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_URL, 'Not IPv4 or IPv6 address', exc_info=True)
            sys.exit(1)

        if self.port < 0 or self.port > 65535:
            logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_URL, 'Invalid port')
            sys.exit(1)

    def get_ip(self):
        logging.info(LogMessage.EXECUTING_PROVIDER, 'sock')

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
                    logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'received', self.attempt + 1, self.retry + 1)
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
                    logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'received', self.attempt + 1, self.retry + 1)
                    if self.attempt < self.retry:
                        self.attempt += 1
                        time.sleep(self.wait_time)
                        return self.get_ip()
                    sys.exit(1)
            s.close()
        except OSError:
            logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'received', self.attempt + 1, self.retry + 1, exc_info=True)
            if self.attempt < self.retry:
                self.attempt += 1
                time.sleep(self.wait_time)
                return self.get_ip()
            sys.exit(1)

        if not data:
            logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'received', self.attempt + 1, self.retry + 1)
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
            logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'matched', self.attempt + 1, self.retry + 1)
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
        logging.debug(LogMessage.INITIALIZING_COMPONENT, type(self).__name__, LogMessage.convert_args(locals()))

        super().__init__(pattern, group)
        self.url = url

        self.retry = 3
        self.attempt = 0
        self.wait_time = 4

        if urlparse(self.url).netloc == '':
            logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_URL, 'No location')
            sys.exit(1)

    def get_ip(self):
        logging.info(LogMessage.EXECUTING_PROVIDER, 'http/s')

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
                    logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'matched', self.attempt + 1, self.retry + 1)
                    if self.attempt < self.retry:
                        self.attempt += 1
                        time.sleep(self.wait_time)
                        return self.get_ip()
                    sys.exit(1)

                self.attempt = 0
                address_match.sort()
                return address_match
            else:
                logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'received correctly', self.attempt + 1, self.retry + 1)
                if self.attempt < self.retry:
                    self.attempt += 1
                    time.sleep(self.wait_time)
                    return self.get_ip()
                sys.exit(1)
        except:
            logging.error(LogMessage.RUNTIME_ERROR_PROVIDER_ADDRESS, 'received', self.attempt + 1, self.retry + 1, exc_info=True)
            if self.attempt < self.retry:
                self.attempt += 1
                time.sleep(self.wait_time)
                return self.get_ip()
            sys.exit(1)


class AddressUpdater(ABC):
    def __init__(self, address, domain, user, password, retry):
        logging.debug(LogMessage.INITIALIZING_COMPONENT, type(self).__name__, LogMessage.convert_args(locals()))

        self.address = address
        self.domain = domain
        self.user = user
        self.password = password
        self.retry = retry

        if self.retry < -1:
            logging.critical(LogMessage.INVALID_CONFIG_UPDATER_RETRY, self.retry)
            sys.exit(1)

    @abstractmethod
    def send_ip(self, ip):
        pass


class DynDNS2Updater(AddressUpdater):
    def __init__(self, address, domain, user, password, retry):
        logging.debug(LogMessage.INITIALIZING_COMPONENT, type(self).__name__, LogMessage.convert_args(locals()))

        super().__init__(address, domain, user, password, retry)
        self.ua = '{c:} - {n:} - {v:}'.format(c='FireSpike0', n=dyncBase.NAME, v=dyncBase.VERSION)

        self.attempt = 0
        self.wait_time = 1800

        if not isinstance(self.domain, list):
            self.domain = list(map(str.strip, self.domain.split(',')))

        if len(self.domain) < 1 or len(self.domain) > 20:
            logging.critical(LogMessage.INVALID_CONFIG_UPDATER_UNSPECIFIED, 'Too few or too many hosts specified.')
            sys.exit(1)

        parse = urlparse(self.address)
        if parse.scheme.lower() not in ['http', 'https'] or parse.netloc == '':
            logging.critical(LogMessage.INVALID_CONFIG_UPDATER_URL, 'Unknown scheme or no location')
            sys.exit(1)

    def send_ip(self, ip):
        logging.info(LogMessage.EXECUTING_UPDATER, ', '.join(ip))

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
            logging.error(LogMessage.RUNTIME_ERROR_UPDATER_SENDING, self.attempt + 1, self.retry + 1, exc_info=True)
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
                logging.info(
                    LogMessage.RUNTIME_INFO_UPDATER_PROTOCOL_MESSAGE,
                    'Successfully updated \'{:}\' to IP address \'{:}\'.'.format(self.domain[domain_index], line.split(' ', 1)[-1])
                )
                update_result.append(True)
                domain_index += 1
            elif line.startswith('nochg'):
                logging.warning(
                    LogMessage.RUNTIME_WARNING_UPDATER_PROTOCOL_MESSAGE,
                    'Updated \'{:}\' to IP address \'{:}\' without a change.'.format(self.domain[domain_index], line.split(' ', 1)[-1])
                )
                update_result.append(True)
                domain_index += 1
            elif line.startswith('notfqdn') and len(self.domain) >= 1:
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'The domain \'{:}\' is not a fully-qualified domain name.'.format(self.domain[domain_index])
                )
                update_result.append(False)
                domain_index += 1
            elif line.startswith('notfqdn') and len(self.domain) < 1:
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'No domains were passed at all.'
                )
                update_result.append(False)
            elif line.startswith('nohost'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'The domain \'{:}\' is not associated with the user account.'.format(self.domain[domain_index])
                )
                update_result.append(False)
                domain_index += 1
            elif line.startswith('numhost'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'The amount of passed hosts exceeds 20 and is thus too high. Normally the program should catch this issue. If you didn\'t modify the program, you should report this.'
                )
                update_result.append(False)
                domain_index += 1
            elif line.startswith('abuse'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'The domain \'{:}\' is blocked because it\'s update mechanism was abused.'.format(self.domain[domain_index])
                )
                update_result.append(False)
                domain_index += 1
            elif line.startswith('good 127.0.0.1') and ','.join(ip) != '127.0.0.1':
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'The user-agent does not follow the specification. Normally the program should catch this issue. If you didn\'t modify the program, you should report this.'
                )
                update_result.append(False)
                domain_index += 1
            elif line.startswith('badagent'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'An unsupported HTTP method was used, or no user-agent was passed.'
                )
                update_result.append(False)
            elif line.startswith('badauth'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'The provided credentials were invalid.'
                )
                update_result.append(False)
            elif line.startswith('badsys'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'This error does either not exist or is not documented very well.'
                )
                update_result.append(False)
            elif line.startswith('!donator'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'A privileged action was requested, but the user is not allowed to perform such an action.'
                )
                update_result.append(False)
            elif line.startswith('dnserr'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'A DNS error occurred during attempt #{:} of #{:}.'.format(self.attempt + 1, self.retry + 1)
                )
                if self.retry == -1 or (self.retry != -1 and self.attempt < self.retry):
                    self.attempt += 1
                    time.sleep(self.wait_time)
                    return self.send_ip(ip)
                update_result.append(False)
            elif line.startswith('911'):
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'A server-side problem occurred, or the server is in maintenance mode during attempt #{:} of #{:}.'.format(self.attempt + 1, self.retry + 1)
                )
                if self.retry == -1 or (self.retry != -1 and self.attempt < self.retry):
                    self.attempt += 1
                    time.sleep(self.wait_time)
                    return self.send_ip(ip)
                update_result.append(False)
            else:
                logging.error(
                    LogMessage.RUNTIME_ERROR_UPDATER_PROTOCOL_MESSAGE,
                    'An unknown return code occurred: \'{:}\'.'.format(line)
                )
                update_result.append(False)

        return all(update_result)


class DynDNSInstance(Thread):
    def __init__(self, iconfig):
        logging.debug(LogMessage.INITIALIZING_INSTANCE, iconfig['uid'])

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
            logging.critical(LogMessage.INVALID_CONFIG_PROVIDER_TYPE, sect['origin'])
            sys.exit(1)

        self.updater = None
        sect = iconfig['server']
        if sect['protocol'].strip().lower() == 'dyndns2':
            self.updater = DynDNS2Updater(sect['address'], sect['domain'], sect['user'], sect['password'], sect['retry'])
        else:
            logging.critical(LogMessage.INVALID_CONFIG_UPDATER_TYPE, sect['protocol'])
            sys.exit(1)

        self.mode = iconfig['mode']

    def exec(self):
        logging.info(LogMessage.STARTING_INSTANCE, self.name)
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
    VERSION = '1.0.0'
    def __init__(self, configfile):
        logging.info(LogMessage.LOADING_CONFIGURATION, configfile)
        if int(yaml.__version__.split('.')[0]) >= 5:
            self.config = yaml.load(open(configfile, mode='r', encoding='utf-8'), Loader=yaml.FullLoader)
        else:
            self.config = yaml.load(open(configfile, mode='r', encoding='utf-8'))
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
        logging.info(LogMessage.STARTING, 'app')
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
            logging.critical(LogMessage.LAUNCH_CRITICAL_FORKING, exc_info=True)
            sys.exit(1)

        os.chdir('/')
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            logging.critical(LogMessage.LAUNCH_CRITICAL_FORKING, exc_info=True)
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
        logging.info(LogMessage.STARTING, 'daemon')

        try:
            with open(self.pidfile, 'r') as f:
                pid = int(f.read().strip())
        except IOError:
            pid = None

        if pid:
            logging.critical(LogMessage.LAUNCH_CRITICAL_STARTING, pid)
            sys.exit(1)

        self.daemonize()
        self.run()

    def stop(self):
        logging.info(LogMessage.STOPPING)

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
                logging.critical(LogMessage.HALT_CRITICAL_STOPPING, exc_info=True)
                sys.exit(1)

    def restart(self):
        logging.info(LogMessage.RESTARTING)
        self.stop()
        self.start()


class Platform():
    CONFIGFILE = None
    PIDFILE = None
    LOGFILE = None

    @staticmethod
    def unix():
        Platform.CONFIGFILE = '/etc/{:}.yaml'.format(dyncBase.NAME)
        Platform.PIDFILE = '/run/{:}.pid'.format(dyncBase.NAME)
        Platform.LOGFILE = '/var/log/{:}.log'.format(dyncBase.NAME)

    @staticmethod
    def windows():
        path = os.path.dirname(os.path.realpath(__file__))
        Platform.CONFIGFILE = '{:}\\{:}.yaml'.format(path, dyncBase.NAME)
        Platform.LOGFILE = '{:}\\{:}.log'.format(path, dyncBase.NAME)

    @staticmethod
    def unknown():
        Platform.unix()


if __name__ == "__main__":
    system = platform.system().lower()
    if system in ['linux', 'freebsd']:
        Platform.unix()
    elif system == 'windows':
        Platform.windows()
    else:
        Platform.unknown()


    main_parser = ArgumentParser(
        prog=dyncBase.NAME,
        description='A simple DynDNS client written in Python 3. Visit https://github.com/FireSpike0/dync for more information.',
        add_help=False
    )

    main_parser.add_argument('-v', '--verbosity', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='set the log verbosity')
    main_parser.add_argument('-c', '--config', default=Platform.CONFIGFILE, help='use a custom configuration')

    subparsers = main_parser.add_subparsers(title='modules', dest='module', required=True)

    app_parser = subparsers.add_parser('app', prog='{:} app'.format(dyncBase.NAME), description='manage the execution as app', add_help=False)
    app_parser.add_argument('command', choices=['start'], help='command to execute')

    daemon_parser = subparsers.add_parser('daemon', prog='{:} daemon'.format(dyncBase.NAME), description='manage the execution as daemon', add_help=False)
    daemon_parser.add_argument('command', choices=['start', 'stop', 'restart'], help='command to execute')

    version_parser = subparsers.add_parser('version', prog='{:} version'.format(dyncBase.NAME), description='show version details', add_help=False)

    help_parser = subparsers.add_parser('help', prog='{:} help'.format(dyncBase.NAME), description='show help about a module', add_help=False)
    help_parser.add_argument('target', nargs='?', default='help', choices=['main', 'app', 'daemon', 'version', 'help'], help='target module')

    args = main_parser.parse_args()


    if args.verbosity == 'DEBUG':
        verbosity = logging.DEBUG
    elif args.verbosity == 'INFO':
        verbosity = logging.INFO
    elif args.verbosity == 'WARNING':
        verbosity = logging.WARNING
    elif args.verbosity == 'ERROR':
        verbosity = logging.ERROR
    elif args.verbosity == 'CRITICAL':
        verbosity = logging.CRITICAL

    logging.basicConfig(filename=Platform.LOGFILE, format='[{asctime:} / {levelname:}] @ {process:}({threadName:}) : {message:}', datefmt='%Y-%m-%d %H:%M:%S', style='{', level=verbosity)

    if args.module == 'app':
        dync = dyncApp(args.config)
        if args.command == 'start':
            dync.start()
    elif args.module == 'daemon':
        dync = dyncDaemon(args.config, Platform.PIDFILE)
        if args.command == 'start':
            dync.start()
        elif args.command == 'stop':
            dync.stop()
        elif args.command == 'restart':
            dync.restart()
    elif args.module == 'version':
        print('{:}\n  version: {:}\n  author: {:}'.format(dyncBase.NAME, dyncBase.VERSION, 'FireSpike0'))
    elif args.module == 'help':
        if args.target == 'main':
            main_parser.print_help()
        elif args.target == 'app':
            app_parser.print_help()
        elif args.target == 'daemon':
            daemon_parser.print_help()
        elif args.target == 'version':
            version_parser.print_help()
        elif args.target == 'help':
            help_parser.print_help()
