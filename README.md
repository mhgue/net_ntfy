# Notifications on mobile phone if connectivity of hosts changes using python and ntfy
Network Notify (*net_ntfy*) is a python script monitoring a list of hosts by ssh connection or by TCP port scan (further methods in future versions).
If one of the hosts connectivity state is changing, a message is send to a mobile phone by [ntfy](https://ntfy.sh/) channel.
This script is a small and easy way to get notified if things change in your network.

As a python script it may run anywhere, but as a linux user I have not tested other platforms.

## Function

<details>
  <summary>Expand</summary>

In a [YAML file](net_ntfy.yaml) the configuration can be written, with
* the ntfy channel
* a list of hosts to check by ssh
* a list of hosts and ports to check by TCP connect
* for each entry a period of time in minutes for repeated check.

If the state of a host is changing (appears or disappears), you get a notification by ntfy on your mobile phone.

</details>

## Intension

<details>
  <summary>Expand</summary>

This script is intended to work on small embedded linux systems to keep track of devices in a personal networking environment.
It is a lightweight script easily running in a python environment very few further dependencies.
If SSH monitoring is used, the ssh command with configured hosts is needed.
The TCP port monitoring is implemented completely inside python.

</details>

## Usage

<details>
  <summary>Expand</summary>

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

### Testing and Debug
The python script [net_ntfy.py](net_ntfy.py) has command line options for debug and diagnosis.
* **-m *n*** With this option the number of seconds per minute can be set to a value different to 60. This can be used to testing in time-lapse (e.g. -m 5), or the other way round to run the script with enlarged check intervals (e.g. -m 120).
* **-c *filename*** Name of the YAML file to read config from. If not provided, a file with the name of the script and the ending `.yaml` is searched in the current working directory and the location of the script.
* **-v** Is a flag for verbose logging of the script actions.
* **-h** Can be used to get a list of the options available.

</details>

## Construction

<details>
  <summary>Expand</summary>

The script is constructed in an OOP manner in classes:
* `Config` A class to guess the location of the configuration file, if not provided explicit. It is reading the file and providing configuration.
* `SendNTFY` A class to send a notification using ntfy service.
* `TimedFunctionQueue` A class providing a timed queue of functions to be called. This enables cooperative execution of many tests with independent periods without the need of multithreading.
* `Test_SSH` A class to execute SSH connection tests.
* `Test_TCP` A class to execute TCP port connection tests.

Further version may provide additional `Test_*` classes.

### Logging
A function decorator is provided for mor detailed logging if **-v** option is used.
The decorator is wrapping the function and logging function calls and returns.
For class member functions the class name is logged.
In addition to the function name their parameters are logged too.

</details>

## License
This script is published unter the [Apache License Version 2.0](LICENSE) or later.

## Related
* [WatchYourLAN](https://github.com/aceberg/WatchYourLAN) *Lightweight network IP scanner with web GUI. Written in Go and TypeScript.*

### Tags
ssh, networking, python3, notification, supervision
