#!/usr/bin/python

# -*- coding: utf-8 -*-

"""
Probe network connections
sudo apt install python3 python3-sh python3-requests

If shall run as a root daemon on a debian system do:
  cd /opt
  git clone https://github.com/mhgue/net_ntfy.git
  cd net_ntfy
  sudo cp net_ntfy.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable net_ntfy.service
  sudo systemctl start net_ntfy.service
Check with
  sudo systemctl status net_ntfy.service
Read log:
  sudo journalctl -u net_ntfy.service

see README.md for more options.

"""

import argparse
import heapq
import inspect
import logging # Prevent using print()
import os
import psutil
import re
import requests
import signal
import socket
import subprocess
import sys
import threading # For locking support only (not multithreading used)
import time
import yaml
from functools import wraps
from scapy.all import ARP, Ether, srp # Used for ARP network scanning

# Decorator to log function entry and exit for members with class name
# and providing parameters in log.
def log_calls(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Determine class name if in a method
        cls_name = None
        if args and hasattr(args[0], "__class__"):
            cls_name = args[0].__class__.__name__
        func_name = func.__name__
        location = f"{cls_name}.{func_name}" if cls_name else func_name

        # Bind arguments using inspect
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        # Remove "self" if present
        if "self" in bound.arguments:
            del bound.arguments["self"]

        params_str = ', '.join(f"{n}={v!r}" for n, v in bound.arguments.items())
        logging.debug(f"Begin: {location}({params_str})")
        result = func(*args, **kwargs)
        logging.debug(f"End  : {location}({params_str})")
        return result
    return wrapper

class ConfigError(Exception):
    def __init__(self, message="YAML Config Failed"):
        self.message = message
        super().__init__(self.message)

# Get configuration from YAML file
class Config:
    def __init__(self, filename = None):
        self._filename = filename
        self.guess_file()
        with open(self._filename, 'r') as f:
            self._data = yaml.safe_load(f)

    # Provide YAML data access by class object subscription.
    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    @log_calls
    def _guess_file(self, filename):
        if os.path.exists(filename):
            self._filename = filename
            logging.info(f"Using {filename}")
            return True  
        
    def guess_file(self):
        if self._filename and os.path.exists(self._filename):
            return
        path = os.path.abspath(sys.argv[0])
        dir = os.path.dirname(path)
        name = os.path.basename(path)
        name = os.path.splitext(name)[0]
        # Check in current working directory.
        # Prio configs enable use of configs not in this repository (private secret).
        if self._guess_file(f"./{name}_prio.yaml"):
            return
        if self._guess_file(f"./{name}.yaml"):
            return
        # Check at script location
        if self._guess_file(f"{dir}/{name}_prio.yaml"):
            return
        if self._guess_file(f"{dir}/{name}.yaml"):
            return
        raise ConfigError(f"No config file (e.g. {name}.yaml)")

# To report observed network incidents to mobile phone using a ntfy channel.
class SendNTFY:
    def __init__(self, channel, host="ntfy.sh", instance=None):
        """
        Initialize sending messages by ntfy.sh

        :param channel: ntfy channel to be used.
        :param host: ntfy server hostname to be used.
        :param instance: name to tag this net_ntfy instance.
        """
        self._ch = channel
        self._host = host
        self._instance = instance
        self._url = f"https://{self._host}/{self._ch}"

    @log_calls
    def send(self, message, title="Urgent", priority="urgent", tags="warning"):
        """
        Sendet eine Nachricht über den Dienst ntfy.sh

        :param message: Content of the message to show.
        :param title: Content of the message title.
        :param priority: Priority of message ["1", ..., "5"] or ["min", "low", "default", "high", "max"|"urgent"]
        :param tags: Tags to show next to the message.
        """
        # Add instance name as a prefix.
        if self._instance:
            message = f'{self._instance}: {message}'
        try:
            response = requests.post( self._url,
                data=message,
                headers={
                    "Title": title,
                    "Priority": priority,
                    "Tags": tags
                })
            response.raise_for_status()  # Wenn der Statuscode nicht 2xx ist, wird eine Ausnahme ausgelöst
            logging.debug(f'Message: "{message}" send.')
            return 0
        except requests.exceptions.RequestException as e:
            logging.warning(f'Message: "{message}" failed: {e}')
            return -1

class SendNTFYs:
    def __init__(self):
        """To report observed network incidents to multiple ntfy channels on multiple servers."""
        self._msg = list()

    def add(self, channel, host="ntfy.sh", instance=None):
        self._msg.append( SendNTFY(channel, host, instance) )
        
    @log_calls
    def send(self, message, title="Urgent", priority="urgent", tags="warning"):
        """"Send message to all configured ntfy channels and servers."""
        if self._msg:
            for m in self._msg:
                m.send(message, title, priority, tags)

class TimedFunctionQueue:
    def __init__(self):
        """ Create a time event scheduler,"""
        self._pq = []
        self._lock = threading.Lock()
    
    #@log_calls
    def schedule(self, delay_s, func, *args, **kwargs):
        """Schedule a function to run after delay_seconds."""
        execution_time = time.time() + delay_s
        with self._lock:
            heapq.heappush(self._pq, (execution_time, func, args, kwargs))

    def _next_s(self):
        
        return self._pq[0][0]
    
    def _until_next_s(self):
        return self._next_s() - time.time()

    def next_s(self):
        with self._lock:
            return self._next_s()
    
    def until_next_s(self):
        with self._lock:
            return self._until_next_s()

    def has_passed(self):
        """Provide top element if time has passed."""
        with self._lock:
            if self._pq and self._until_next_s() <= 0:
                return heapq.heappop(self._pq)
        return None
    
    def run_one_pending(self):
        e = self.has_passed()
        if e:
            execution_time, func, args, kwargs = e
            # Important to call from outside the _lock
            # to enable periodic rescheduling functions.
            func(*args, **kwargs)
            return True
        return False

    def run_pending(self):
        """Run all functions whose scheduled time has passed."""
        count=0
        while self.run_one_pending():
            count += 1
        return count
    
    def is_empty(self):
        with self._lock:
            return len(self._pq) == 0

    @log_calls
    def dump(self):
        with self._lock:
            for e in self._pq:
                logging.info(f'Event: {e}')

class HostInfo:
    def __init__(self):
        """Collect and provide host information."""
        # Initialize pattern
        self._ipv4_pattern = re.compile(r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        self._ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
        self._mac_pattern = re.compile(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$')
        # Dictionary of names of addresses (mac or ip).
        self._name = dict()
        # Set of names or addresses to be ignored.
        self._ignore = set()
        # Read YAML and fill set and dictionary.
        if ('host' in config) and config['host']:
            try:
                for h in config['host']:
                    if ('ignore' in h) and h['ignore']:
                        for tag in ['ip', 'mac', 'name']:
                            if tag in h:
                                self._ignore[self.clean(h[tag])]
                    if ('name' in h) and h['name']:
                        for tag in ['ip', 'mac']:
                            if tag in h:
                                self._name[self.clean(h[tag])] = h['name']
            except TypeError:
                logging.fatal(f'YAML Fail: host needs to be an array')
        
    def __getitem__(self, addr):
        addr = self.clean(addr)
        # If not known by config and valid IP address, try by DNS
        if not addr in self._name and self.is_ip(addr):
            try:
                hostname, _, _ = socket.gethostbyaddr(addr)
                self._name[addr] = hostname
            except socket.error as e:
                logging.warning(f'DNS Failed to get name of {addr}: {e}')
        if addr in self._name:
            return f'{self._name[addr]} ({addr})'
        else:
            return addr

    def __contains__(self, addr):
        return addr in self._name

    def clean(self, s):
        return re.sub(r'\s+', '', s).lower()

    def is_ipv4(self, addr):
        return bool(self._ipv4_pattern.match(addr))

    def is_ipv6(self, addr):
        return bool(self._ipv6_pattern.match(addr))

    def is_ip(self, addr):
        return self.is_ipv4(addr) or self.is_ipv6(addr)

    def is_mac(self, addr):
        return bool(self._mac_pattern.match(addr))

    def is_addr(self, addr):
        return self.is_ip(addr) or self.is_mac(addr)
 
    def do_ignore(self, addr):
        return self.clean(addr) in self._ignore

    def get_ip_from_mac(self, target_mac, target_ip_range="192.168.1.1/24"):
        # Create an ARP request to get the MAC address of the device
        arp_request = ARP(pdst=target_ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send the request and get the response
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        for element in answered_list:
            if element[1].hwsrc.lower() == target_mac.lower():
                return element[1].psrc  # IP Address

        return None  # If no IP was found

# Do test host by using a ssh connection as setup in .ssh/config (with key and agent running)
class Test_SSH:
    def __init__(self):
        self._return_codes = dict()
        self._user_ssh_sock = dict()

    def cleanup_string(self, s):
        return s.decode('utf-8').strip().replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

    # Do find the ssh agent of another user to prevent from asking for passphrase.
    @log_calls
    def get_user_ssh_sock(self, user, sock_type=None):
        if user in self._user_ssh_sock:
            return self._user_ssh_sock[user]
        else:
            # iterate user's processes
            pids = subprocess.check_output(['pgrep', '-u', user]).split()
            for pidb in pids:
                pid = pidb.decode()
                try:
                    with open(f'/proc/{pid}/environ', 'rb') as f:
                        env = f.read().split(b'\x00')
                    for e in env:
                        if e.startswith(b'SSH_AUTH_SOCK='):
                            value = e.split(b'=',1)[1].decode()
                            logging.debug(f'user: {user}, socket: {value}')
                            if sock_type:
                                if sock_type in value:
                                    self._user_ssh_sock[user]=value
                                    return value
                            else:
                                self._user_ssh_sock[user]=value
                                return value
                except Exception:
                    continue
        return None

    @log_calls
    def probe(self, host, user=None, sock_type=None):
        try:
            # Run ssh as subprocess with sudo if requested.
            if user and user != 'root':
                user_sock = self.get_user_ssh_sock(user, sock_type)
            if user and user_sock:
                logging.debug(f'Running ssh as user {user} using {user_sock}')
                result = subprocess.run(
                    # Der "exit"-Befehl beendet die Verbindung nach einem erfolgreichen Login
                    [ 'sudo', '-u', user, 'env', f'SSH_AUTH_SOCK={user_sock}', 'ssh', host, 'exit' ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    # Timeout nach 10 Sekunden
                    timeout=15
                )
            else:
                result = subprocess.run(
                    # Der "exit"-Befehl beendet die Verbindung nach einem erfolgreichen Login
                    ["ssh", host, "exit"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    # Timeout nach 10 Sekunden
                    timeout=15
                )
            # Prüfe, ob der Befehl erfolgreich war (Rückgabewert 0 bedeutet Erfolg)
            if result.returncode == 0:
                return 0
            else:
                logging.error(f"{self.cleanup_string(result.stderr)}")
                return result.returncode
        except subprocess.TimeoutExpired:
            return -1
        except Exception as e:
            logging.error(f"SSH Unknown error {e}")
            return -2

    @log_calls
    def test(self, period_s, host, user = None, sock_type = None):
        # If running as root do change user for ssh usage.
        if os.geteuid() == 0:
            return_code = self.probe(host, user, sock_type)
        else:
            return_code = self.probe(host)
        # Do we have already tested this host?
        if host in self._return_codes:
            if return_code != self._return_codes[host]:
                if return_code == 0:
                    msg.send(f"SSH {hi[host]} result {self._return_codes[host]} => {return_code}",
                            "SSH up", "high", "green_circle")
                else:
                    msg.send(f"SSH {hi[host]} result {self._return_codes[host]} => {return_code}",
                            "SSH down", "high", "red_circle")
                self._return_codes[host] = return_code
        else:
            self._return_codes[host] = return_code
        # Schedule again.
        tq.schedule(period_s, self.test, period_s, host, user)

# Do test host by connecting a TCP port (e.g. ssh=22, http=80, https=443, ...)
# like e.g. "nc -zv google.de 443" on CLI
class Test_TCP:
    def __init__(self):
        self._return_codes = dict()

    @log_calls
    def probe(self, host, port=22, timeout_s=5):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            s.connect((host, port))
            s.close()
            return 0
        except (socket.timeout, socket.error):
            return -1

    @log_calls
    def test(self, period_s, host, port):
        return_code = self.probe(host, port)
        if (host, port) in self._return_codes:
            if return_code != self._return_codes[(host, port)]:
                if return_code == 0:
                    msg.send(f"TCP {hi[host]}:{port} result {self._return_codes[host]} => {return_code}",
                            "Host up", "high", "green_circle")
                else:
                    msg.send(f"TCP {hi[host]}:{port} result {self._return_codes[host]} => {return_code}",
                            "Host down", "high", "red_circle")
                self._return_codes[(host, port)] = return_code
        else:
            self._return_codes[(host, port)] = return_code
        # Schedule again.
        tq.schedule(period_s, self.test, period_s, host, port)

class Test_ARP:
    def __init__(self):
        self._default_target_net = self.get_ip_and_cidr()
        # Already seen devices with (MAC, seen counter)
        self._devices = dict()
        # Scanned networks number of runs
        self._net_run = dict()

    def get_default_route_ip(self):
        """Get the local IP address used for the default route."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to a public IP (Google DNS), no packets are sent
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

    def get_netmask_of_ip(self, ip):
        """Loop through network interfaces and find the netmask for the IP."""
        for iface, info_list in psutil.net_if_addrs().items():
            for info in info_list:
                if info.family == socket.AF_INET and info.address == ip:
                    return info.netmask

    def get_netmask_prefix_length(self, netmask):
        """Count leading bits of netmask."""
        netmask_bin = ''.join(f'{int(octet):08b}' for octet in netmask.split('.'))
        return netmask_bin.count('1')

    def get_ip_and_cidr(self):
        default_ip = self.get_default_route_ip()
        netmask = self.get_netmask_of_ip(default_ip)
        netmask_length = self.get_netmask_prefix_length(netmask)
        return f"{default_ip}/{netmask_length}"

    #@log_calls
    def test(self, period_s, timeout, scans, validate, target_net = None):
        if not target_net:
            target_net = self._default_target_net
        # Count network scans per network.
        self._net_run[target_net] = self._net_run.get(target_net, 0) + 1
        # Increment last seen counter (in place)
        for ip in self._devices.keys():
            self._devices[ip] = (self._devices[ip][0], self._devices[ip][1] + 1)
        # Do ARP broadcast request
        logging.debug(f"ARP scan {target_net}")
        arp = ARP(pdst=target_net)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        devices = dict()
        # Repeat scanning
        for n in range(scans):
            answered = srp(packet, timeout=timeout, verbose=0)[0]
            for sent, received in answered:
                if (not hi.do_ignore(received.hwsrc)) and (not hi.do_ignore(received.psrc)):
                    devices[received.psrc] = received.hwsrc
        # Look for devices seen
        for ip in devices.keys():
            # This is an already known IP
            if ip in self._devices:
                # Using changed MAC address
                if self._devices[ip][0] != devices[ip]:
                    msg.send(f"{hi[ip]} changed mac {hi[self._devices[ip][0]]} => {hi[devices[ip]]}",
                         "MAC Change", "high", "arrows_counterclockwise")
                    # Mark as seen right now with new MAC
                    self._devices[ip] = (devices[ip], 0)
                else:
                    # Reset seen counter
                    self._devices[ip] = (self._devices[ip][0], 0)
            else:
                # Add new device as seen right now.
                self._devices[ip] = (devices[ip], 0)
                # If network is validated do report new device.
                if self._net_run[target_net] >= validate:
                    msg.send(f'{hi[ip]} appeared {hi[self._devices[ip][0]]}', 
                             "New IP", "high", "green_circle")
        # Look for devices not seen for validation period.
        for ip in list(self._devices.keys()):
            if self._devices[ip][1] >= validate:
                msg.send(f'{hi[ip]} disappeared {hi[self._devices[ip][0]]}',
                         "IP Gone", "high", "red_circle")
                del self._devices[ip]
        # Schedule again.
        tq.schedule(period_s, self.test, period_s, timeout, scans, validate, target_net)

# Clean stop
def stop():
    logging.info(f"{sys._getframe().f_code.co_name}()")
    msg.send("Stop network notification", "Stop", "default", "stop_sign,stop_sign")
    sys.exit(0)

def signal_handler(sig, frame):
    stop()

def main():
    # Command line option parsing (provide global)
    parser = argparse.ArgumentParser(description="Network resources monitoring and reporting.")
    parser.add_argument("-c", "--config", type=str,
                        help='YAML configuration file')
    parser.add_argument("-m", "--min", type=int, default=60,
                        help="Seconds per minute, for testing with time-lapse")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="increase output verbosity")
    global args
    args = parser.parse_args()

    # Set logging level. Debug if verbose requested.
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")
    else:
        logging.basicConfig(level=logging.INFO)

    # Do handle Ctrl-C interrupt signal.
    signal.signal(signal.SIGINT, signal_handler)

    # Do read global config
    global config
    config = Config(args.config)
    # Global timed queue
    global tq
    tq = TimedFunctionQueue()
    # Global host info
    global hi
    hi = HostInfo()

    # Global messaging
    global msg
    msg = SendNTFYs()
    if ('ntfy' in config) and config['ntfy']:
        try:
            for e in config['ntfy']:
                # ntfy host. Default is main public server in USA.
                host = e.get('host', 'ntfy.sh')
                # This instance to distinguish if sharing channel.
                instance = e.get('instance', None)
                if not 'channel' in e:
                    logging.fatal(f'YAML Fail: ntfy entry without channel is ignored')
                else:
                    msg.add(e['channel'], host, instance)
        except TypeError:
            logging.fatal(f'YAML Fail: ntfy needs to be an array')

    # If called via sudo, do use original user as default.
    default_user = os.environ.get("SUDO_USER")
    # Schedule tests to be done.
    ts = Test_SSH()
    if ('ssh' in config) and config['ssh']:
        for e in config['ssh']:
            # Default is 5 minutes period
            period_s = e.get('period', 5)*args.min
            # Do execute ssh as given user. Default is to use the original user before sudo.
            user = e.get('user', default_user)
            # Do specify the socket type to look for (e.g. '/keyring/', '/gnupg/', '/gcr/')
            sock_type = e.get('sock_type', None)
            if not 'host' in e:
                logging.fatal(f'YAML Fail: ssh entry without host is ignored')
            else:
                tq.schedule(period_s, ts.test, period_s, e['host'], user, sock_type)
    tt = Test_TCP()
    if ('tcp' in config) and config['tcp']:
        for e in config['tcp']:
            # Default is 5 minutes period
            period_s = e.get('period', 5)*args.min
            # Default port is SSH (22)
            port = e.get('port', 22)
            if not 'host' in e:
                logging.fatal(f'YAML Fail: tcp entry without host is ignored')
            else:
                tq.schedule(period_s, tt.test, period_s, e['host'], port)
    ta = Test_ARP()
    if ('arp' in config) and config['arp']:
        for e in config['arp']:
            # Default is 5 minutes period
            period_s = e.get('period', 5)*args.min
            # Default is network of default route
            net = e.get('net', None)
            # Default is 3 seconds timeout of ARP request
            timeout = e.get('timeout', 3)
            # Default is 3 times repeating ARP request
            scans = e.get('scans', 3)
            # Default is state change report after 5 observations.
            validate = e.get('validate', 5)
            tq.schedule(period_s, ta.test, period_s, timeout, scans, validate, net)

    try:
        # Do report start of test.
        msg.send("Start network notification", "Start", "default", "eyes")

        # Do run the event scheduler.
        while not tq.is_empty():
            tq.run_pending()
            delay_s = tq.until_next_s()
            if delay_s > 0:
                logging.debug(f"Sleep for {delay_s:.1f} s")
                time.sleep(delay_s)
    # Just as a dummy.
    except ConfigError as e:
        logging.fatal(f'Exception: {e}')
        msg.send(f'Exception: {e}', "Exception", "max", "scream")
        stop()
    except Exception as e:
        logging.fatal(f'Exception: {e}')
        msg.send(f'Exception: {e}', "Exception", "max", "scream")
        stop()

if __name__ == "__main__":
    main()

#EOF
