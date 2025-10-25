#!/usr/bin/python

# -*- coding: utf-8 -*-

"""
Probe network connections
sudo apt install python3 python3-sh python3-requests

"""

import subprocess
import heapq
import time
import threading # For locking only
import requests
import signal
import sys
import os
import argparse
import logging # Prevent using print()
from functools import wraps
import inspect
import socket
import yaml

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
        logging.debug(f"Entering: {location}({params_str})")
        result = func(*args, **kwargs)
        logging.debug(f"Exiting:  {location}({params_str})")
        return result
    return wrapper

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
        logging.critical(f"No config file (e.g. {name}.yaml)")
        sys.exit(1)
        
    def dump(self):
        print(self._data)

# To report observed network incidents to mobile phone.
class SendNTFY:
    def __init__(self, channel, host="ntfy.sh"):
        """
        Initialize sending messages by ntfy.sh

        :param channel: ntfy channel to be used.
        """
        self._ch = channel
        self._host = host
        self._url = f"https://{self._host}/{self._ch}"

    # Send message by https://ntfy.sh/
    @log_calls
    def send(self, message, title="Urgent", priority="urgent", tags="warning"):
        """
        Sendet eine Nachricht über den Dienst ntfy.sh

        :param message: Content of the message to show.
        :param title: Content of the message title.
        :param priority: Priority of message ["1", ..., "5"] or ["min", "low", "default", "high", "max"|"urgent"]
        :param tags: Tags to show next to the message.
        """
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

# Do test host by using a ssh connection as setup in .ssh/config (with key and agent running)
class Test_SSH:
    def __init__(self):
        self._return_codes = dict()

    def cleanup_string(self, s):
        return s.decode('utf-8').strip().replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

    @log_calls
    def probe(self, host):
        try:
            # Verwende subprocess, um den SSH-Befehl auszuführen
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
    def test(self, host, period_s):
        return_code = self.probe(host)
        if host in self._return_codes:
            if return_code != self._return_codes[host]:
                msg.send(f"{host} ssh {self._return_codes[host]} => {return_code}",
                         "Change", "high")
                self._return_codes[host] = return_code
        else:
            self._return_codes[host] = return_code
        # Schedule again.
        tq.schedule(period_s, self.test, host, period_s)

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
    def test(self, host, port, period_s):
        return_code = self.probe(host, port)
        if (host, port) in self._return_codes:
            if return_code != self._return_codes[(host, port)]:
                msg.send(f"{host}:{port} {self._return_codes[host]} => {return_code}",
                         "Change", "high")
                self._return_codes[(host, port)] = return_code
        else:
            self._return_codes[(host, port)] = return_code
        # Schedule again.
        tq.schedule(period_s, self.test, host, port, period_s)

# Clean stop
def stop():
    logging.info(f"{sys._getframe().f_code.co_name}()")
    msg.send("Stop watching", "Stop", "default", "heavy_check_mark")
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

    # Do read config
    config = Config(args.config)
    #config.dump()

    # Global timed queue and messaging
    global tq
    tq = TimedFunctionQueue()
    global msg
    msg = SendNTFY(config['ntfy']['channel'])

    # Schedule tests to be done.
    ts = Test_SSH()
    for e in config['ssh']:
        tq.schedule(args.min*e['period'], ts.test, e['host'], args.min*e['period'])
    tt = Test_TCP()
    for e in config['tcp']:
        tq.schedule(args.min*e['period'], tt.test, e['host'], e['port'], args.min*e['period'])

    # Do report start of test.
    msg.send("Start watching", "Start", "default", "heavy_check_mark")

    # Do run the event scheduler.
    while not tq.is_empty():
        tq.run_pending()
        delay_s = tq.until_next_s()
        if delay_s > 0:
            logging.debug(f"Sleep for {delay_s:.1f} s")
            time.sleep(delay_s)

if __name__ == "__main__":
    main()

#EOF
