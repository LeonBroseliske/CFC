## Centralized Firewall Control script

Centralized firewall control provides a centralized way to manage the firewall on multiple servers or loadbalancers running iptables. This way you can quickly allow/block/del/search abuse ranges etc. with one command on several servers.
It accesses those servers through ssh.

It supports both IPv4 and IPv6.

Tested on Debian 6.x / 7.x / 8.x / 9.x, but should work on any distro.

## Prerequisites

To use the 'precheck', 'protected' and 'findip' functions for IPv6, you need the 'netaddr' python module installed. The IPv4 does not need that since it uses prefix matching on the binary form of the IP.

Debian: apt-get install python3-netaddr

It's more efficient to use 'ipset' in addition to iptables. Ipset can be used to manage lists that iptables can refer to and use. This works faster and manipulation of the list is also more flexible and the preferred method of using this script.

Debian: apt-get install ipset

Since this script connects to the given servers with ssh, such access must be present before it can be used.

## Settings

Copy the example config from cfc.cfg-example to cfc.cfg the first time.

The following settings can be set in the config file:

* action: sets the action when adding a rule, default: DROP
* checkaggrbin: path to the checkaggr.py script, default: ./checkaggr.py
* cleanupconfirmation: asks for confirmation before running the clean command, set to false for cron usage, default: true
* date: set the date format for the firewall comments, default: $(date +%d%m%Y) -> 22062016
* dateipset: set the date format for the ipset firewall comments, leave this on the default to avoid breaking some of the functions, default: $(date +%Y%m%d) -> 20160622
* ipsetname: sets the IPSET list name, default: blockedips
* ipsetservers: sets the servers that use IPSET instead of iptables, default: "lvs05.example.com lvs06.example.com"
* fwchain: name of the firewall chain to add/del/search, default: INPUT
* masklimit: max size of the ip ranges that can be added, default: /21
* precheck: check if the ip that is about to be added is already in the firewall or part of a larger added range, might be a bit slow on large firewalls on IPv6 (~25 sec. for searching 500 ip ranges per server), default: true
* protected: enable the added protected ranges, default: true
* protectedranges: ip ranges that are excluded from the 'add' function, usually the ranges owned by the local network, default: "172.16.0.0/12 10.0.0.0/8 192.168.0.0/16"
* pythonbin: location of the used Python binary, default: /usr/bin/python3
* servers: sets the servers that use iptables only, default: "lvs01.example.com lvs02.example.com lvs03.example.com lvs04.example.com"

* The IPv6 functions are marked with the '6' suffix

## Usage

When entering IPs/ranges with the following commands, do so in CIDR notation, this gets validated and won't accept anything else.

add:

	cfc.sh add n.n.n.n/NN '<optional comment>'
	cfc6.sh add <IPv6_address_range> '<optional comment>'

Adds the given IP(range) to the firewalls with the configured action for all traffic from that source. Makes a comment by default with the current date, you can add an optional comment using single quotes to add a reason or owner of that range as an example. It can also be searched on that comment later on.

addstring:

	cfc.sh addstring <protocol>:<dport> <string>

Adds a string block to iptables for a certain protocol and destination port. A practical example would be blocking a User-Agent destined for a bunch of webservers, so a tcp connection destined for port 80 with the string: Firefox/28.0, all incoming traffic matching that string towards tcp port 80 would be blocked:

	cfc.sh addstring tcp:80 'Firefox/28.0'

Beware, this can have big consequences if the string is not specific enough!

clean:

	cfc.sh clean <older_than_number_of_days>

Cleans all the CFC firewall rules older than n amount of days. Keep in mind that it depends on the default date format! So if you customized the date format, you will need to adjust the script in the 'clean' section.

del:

	cfc.sh del n.n.n.n/NN
	cfc6.sh del <IPv6_address_range>

Deletes the given IP(range)/rule from the firewalls

delstring:

	cfc.sh delstring <protocol>:<dport> <string>

Deletes a string block in iptables for a certain protocol and destination port.

find:

	cfc.sh find <string>
	cfc6.sh find <string>

Searches the firewalls for the given string (case in-sensitive), this can be (part of) an IP / range / comment

findip:

	cfc.sh findip n.n.n.n/NN
	cfc6.sh findip <IPv6_address_range>

Searches the firewalls if the given IP(range) is already part of an added rule, might be a bit slow on large firewalls for IPV6 (~25 sec. for searching 500 ip ranges per server). IPv4 uses prefix matching on the binary form of the IP instead which is roughly 500% faster, this is also used for the precheck and protectedranges features.

ipsethostinit:

	cfc.sh ipsethostinit <server_name>
	cfc6.sh ipsethostinit <server_name>

Adds an IPSET list to the specified host and an iptables rule referring to it using the parameters defined in the cfc.cfg. This only needs to be done once before adding firewall rules.

last:

	cfc.sh last <nr_of_most_recent_rules>
	cfc6.sh last <nr_of_most_recent_rules>

Shows the last <n> entries added to the firewalls
