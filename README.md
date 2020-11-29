# bvssh-wfas-bridge

A Python 3.8 script for blacklisting IPs that connect to a Bitvise SSH Server 
using a banned client version string. It does this by monitoring BvSSH's logs 
and then configuring Windows Firewall to block incoming data from those IPs.

## Environment

* Windows 10 Pro
* Python 3.8.0
* [Bitvise SSH Server](https://www.bitvise.com/ssh-server) 8.43

## Usage

Accessing the logs and updating the firewall rules both require Administator 
privileges. To run, open CMD as Administrator and run:

```text
python bvssh-wfas-bridge.py
```

A directory can optionally be added to configure the BvSSH log directory if 
BvSSH wasn't installed in its default location,
`C:\Program Files\Bitvise SSH Server\Logs`.

## Help

```text
$ python bvssh-wfas-bridge.py -h
usage: bvssh-wfas-bridge.py [-h] [directory]

positional arguments:
  directory   The Bitvise SSH Server log directory.

optional arguments:
  -h, --help  show this help message and exit
```

## How it works

BvSSH's logs are monitored for certain `<event>` elements including those for 
log rotation, server shut down, and client version violations. If a violation 
is logged, the IP is extracted and added to Windows Firewall via `netsh`.

### Complications

#### Logs

BvSSH's logs are in XML format and it does automatic log rotation. It handles 
this by updating the files to insert `<event>` elements before the root closing 
tag. Handling this with usual XML parsers is tricky if you want to be more 
elegant than simply reading the entire file repeatedly. `xml.sax` makes this 
feasible.

#### Windows Firewall

It's easy enough to configure the firewall via `netsh` but there are some 
limitations, the main one being that the IP list is limited to ~8000 
characters. The command as a whole has a larger buffer (~32000 seems to be the 
limit for that), but `netsh` seems to have an internal limit. There's a COM 
interface but that's a whole other mess. Currently, the command length is 
tracked and, if it gets too long, the script will start a new rules. Of course, 
this also means it needs to check for existing rules so it can pick up where it 
left off when restarted.

#### Python on Windows

I'm not sure Python is the best choice for this. It works great for quickly 
creating a proof of concept and working out implementation details but .NET 
may be a better choice for a final app given that this is strictly a Windows 
tool. IronPython would have been nice but it's still being updated to Python 3 
and so isn't production ready yet (see 
[ironpython3 on GitHub](https://github.com/IronLanguages/ironpython3)).
