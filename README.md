# Notifications on mobile phone if connectivity of hosts changes using python and ntfy
Network Notify (*net_ntfy*) is a python script monitoring
* a list of hosts by ssh connection or 
* a list of hosts by TCP port scan or
* a list of networks by ARP scan.

If one of the hosts connectivity state is changing, a message is send to a mobile phone by [ntfy](https://ntfy.sh/) channel.
This script is a small and easy way to get notified if things change in your network.

As a python script it may run anywhere, but as a linux user I have not tested other platforms.
If using ARP scan, that will need `root` privileges, together with SSH of a different user, there will be some very linux depending commands used.

## Function

In a [YAML file](net_ntfy.yaml) the configuration can be written, with
* the ntfy channel
* a list of hosts to check by ssh
* a list of hosts and ports to check by TCP connect
* a list of networks to monitor by ARP scan
* for each entry above a period of time in minutes for repeated check.
* a list of MAC or IP addresses to be ignored

If the state of a host is changing (appears or disappears), you get a notification by ntfy on your mobile phone.

## Intension and Requirements

This script is intended to work on small embedded linux systems to keep track of devices in a personal networking environment.
It is intended to run on any device on the network without special interfaces or privileges.
It is a lightweight script easily running in a python environment with very few further dependencies.
If SSH monitoring is used, the ssh command with configured hosts in `.ssh/config` is needed.
For SSH logon keys and an agent shall be in operation.
The TCP port monitoring is implemented completely inside python without further needs.
The ARP scan needs `root` privileges.

This script may run with some restrictions (see [Users to use](#users-to-use)) as a daemon process on any linux device.
It may operate a as network monitoring service on a home server or any other small device (Raspberry Pi, NanoPi, ...).

## Usage

* Get from here `git clone https://github.com/mhgue/net_ntfy.git`
* Edit [net_ntfy.yaml](net_ntfy.yaml) to fit own ntfy channel and hosts to monitor.
* Install Python3 and needed modules (see [requirements.txt](requirements.txt)).
* Run [net_ntfy.py](net_ntfy.py)

For easy usage there is a [bash script](net_ntfy.sh) that creates a python virtual environment and installs dependencies inside.
So the convenient usage is:
* `git clone https://github.com/mhgue/net_ntfy.git`
* edit [net_ntfy.yaml](net_ntfy.yaml)
* run [net_ntfy.sh](net_ntfy.sh)

### Using ntfy
To use ntfy you need to install the [ntfy app](https://play.google.com/store/apps/details?id=io.heckel.ntfy&hl=en) on your mobile phone and create a channel name.
This channel name must be entered in the [YAML config file](net_ntfy.yaml).

### Using ARP Scans
To perform an ARP scan, the script needs to be executed with `root` privileges.
Therefore is must be started with `sudo` or from a service already provided with `root` privileges.

CAUTION: You should not execute any script from Github et al. with `root` privileges!
So this is the perfect moment to have a look at the source code to find out if you can trust this script.
This is one of the reasons, why scripts like this are made in one file and hopefully reasonable readable.
You may ask an AI if you can trust this script, just as an additional opinion.
Make sure this script doesn't kill small cats or doing any other harm to your surroundings.

### Testing and Debug
The python script [net_ntfy.py](net_ntfy.py) has command line options for debug and diagnosis.
* **-m *n*** With this option the number of seconds per minute can be set to a value different to 60. This can be used for testing in time-lapse (e.g. -m 5), or the other way round to run the script with enlarged check intervals (e.g. -m 120) for temporary lower workload.
* **-c *filename*** Name of the YAML file to read config from. If not provided, a file with the name of the script and the ending `.yaml` is searched in the current working directory and the location of the script.
* **-v** Is a flag for verbose logging of the script actions. It is setting the logging level to `DEBUG`.
* **-h** Can be used to get a list of the options available.

### Run as systemd Daemon
This script is most useful if running no a permanently powered Linux host as a daemon process.
This can be a very tiny Linux host.
There are two way to do so:
* If all python modules are installed on the system, the python script can be installed as a `systemd` service:

```bash
sudo su -
cd /opt
git clone https://github.com/mhgue/net_ntfy.git
cd net_ntfy
# Edit net_ntfy.yaml for your needs and ntfy channel.
cp net_ntfy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable net_ntfy.service
systemctl start net_ntfy.service
# Check with
systemctl status net_ntfy.service
# Read log
journalctl -u net_ntfy.service
```
* If modules shall not be installed for the entire system:
```bash
sudo su -
# Install python3 and virtual environment
apt install python3 python3-venv
cd /opt
git clone https://github.com/mhgue/net_ntfy.git
cd net_ntfy
# Edit net_ntfy.yaml for your needs and ntfy channel.
# Run creating a virtual environment
./net_ntfy.sh
# There should be a start message on your ntfy app.
# Do stop using Ctrl-C
# There should be a stop message on your ntfy app.
cp net_ntfy_venv.service /etc/systemd/system/net_ntfy.service
systemctl daemon-reload
systemctl enable net_ntfy.service
systemctl start net_ntfy.service
# There should be a start message on your ntfy app.
# Check with
systemctl status net_ntfy.service
# Read log
journalctl -u net_ntfy.service
```

## Configuration

Configuration is done by a YAML file.
This file may be provided by **-c *filename***.
If not provided by command line, there is a list of locations and names where the script is looking for a config file:
* `./net_ntfy_prio.yaml` *Basename of script without `.py` (even if changed) with `_prio.yaml` appended in current directory.*
* `./net_ntfy.yaml` *Basename of script without `.py` (even if changed) with `.yaml` appended in current directory.*
* *script_dir*`/net_ntfy_prio.yaml` *Basename of script without `.py` (even if changed) with `_prio.yaml` appended in the same directory as the script is located.*
* *script_dir*`/net_ntfy_prio.yaml` *Basename of script without `.py` (even if changed) with `.yaml` appended in the same directory as the script is located.*

The file shall be in [YAML format](https://en.wikipedia.org/wiki/YAML) and may contain the following entries:
* `ntfy:` with the parameter `channel:` to provide the ntfy channel to be used.
* `ssh:` a list of entries with parameters
  * `host:` Name of the ssh connection as defined in your `.ssh/config`. This is the only parameter needed.
  * `period:` Period of time in minutes for periodic check of this SSH connection.
  * `user:` User to execute `ssh` command if running as `root`. Default is not to change the user or if called via `sudo` use the original user from `SUDO_USER` environment variable.
  * `sock_type:` Substring of the path to the SSH agents socket to be used (e.g. '/keyring/', '/gnupg/', '/gcr/'). This is needed if there are several sockets used and the correct type needs to be identified.
* `tcp:` a list of entries with parameters
  * `host:` Hostname or IP address of the device to monitor. This is the only parameter needed.
  * `port:` Port to be monitored. Default is 22 for SSH. You may use 80 for HTTP, 443 for HTTPS or any other.
  * `period:` Period of time in minutes for periodic check of this TCP port connection.
* `arp:` a list of networks to be monitored by ARP scan.
  * `net:` Network address in [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) notation (e.g. `192.168.1.0/24`). The default is to use the network used as default route.
  * `period:` Period of time in minutes for periodic check of this network.
  * `timeout:` Time in seconds to wait for ARP request reply.
  * `scan:` Number of times to repeat the ARP request and accumulate results.
  * `validation:` Number of consecutive attempts to assume a device as being disappeared.
* `ignore:` a list of entries to be ignored for detection and reporting on ARP scans. Not networks or wildcards supported.
  * `mac:` MAC address to be ignored
  * `ip:` IP address to be ignored

Do read the [example provided here](net_ntfy.yaml).

### Users to use
This script can be executed in three different ways:
* As an **ordinary non privileged user**. In this way the ARP scan can not be used for monitoring.
* As **`root` user using `root` SSH**. In this way ARP scan and SSH probes can be used, but there must be a ssh agent running for SSH key used by `root`. This configuration is not very save.
* As **`root` user** but using **non privileged users SSH**. This is a litte complicated, because the `root` user needs to find out the SSH agents socket of the non privileged user.

Probing SSH connections is not practical for operation of the script as a daemon.
There will be no one to enter the passphrase on system startup.
Therefore if running as a daemon there are three options:
* Running with SSH keys without passphrase. Do not even think about this. It is far too insecure.
* Running as `root` using a combination of **TCP probes and ARP scan** only.
* Running as a non privileged user using **TCP port probes only**. By far the saves setup.

## Construction

The script is constructed in an OOP manner in classes:
* `Config` A class to guess the location of the configuration file, if not provided explicit. It is reading the file and providing configuration.
* `SendNTFY` A class to send a notification using ntfy service.
* `TimedFunctionQueue` A class providing a timed queue of functions to be called. This enables cooperative execution of many tests with independent periods without the need of multithreading.
* `Test_TCP` A class to execute **TCP** port connection tests.
* `Test_SSH` A class to execute **SSH** connection tests.
* `Test_ARP` A class to execute **ARP** scans of networks.

Further version may provide additional `Test_*` classes.

### Logging
A function decorator is provided for more detailed logging if **-v** option is used.
The decorator is wrapping the function and logging function calls and returns with their parameters.
For member functions the class name is logged.

## ToDo
Collection of things that may be nice and if there is enough time may appear here:
* Do support other ntfy hosts (not just ntfy.sh) by YAML config.
* Do provide host names from DNS and/or YAML for IP and/or MAC.
* Do provide instance name if running on several hosts using same ntfy channel.
* Do support probing UDP ports.

## License
This script is published unter the [Apache License Version 2.0](LICENSE) or later.

## Related
* [ntfy](https://ntfy.sh/), [@Github](https://github.com/binwiederhier/ntfy) *Send push notifications to your phone or desktop via PUT/POST. Written in Go and JavaScript*
* [WatchYourLAN](https://github.com/aceberg/WatchYourLAN) *Lightweight network IP scanner with web GUI. Written in Go and TypeScript.*

### Tags
ssh, networking, python3, notification, supervision
