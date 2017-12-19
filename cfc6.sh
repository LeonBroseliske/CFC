#!/bin/bash

#####################################
#                                   #
# Centralized Firewall Control IPv6 #
#                                   #
#####################################

if [ "$1" = "" ] || [ "$2" = "" ]; then
	echo "Usage: ./cfc6.sh add <IPv6_address_range> '<optional_comment>'"
	echo "       ./cfc6.sh del <IPv6_address_range>"
	echo "       ./cfc6.sh find <string>"
	echo "       ./cfc6.sh findip <IPv6_address_range>"
	echo "       ./cfc6.sh ipsethostinit <server_name>"
	echo "       ./cfc6.sh last <nr_of_most_recent_rules>"
	exit 1
fi

# Settings
source cfc.cfg

mode=$1
iprange=$2
comment=$3
cidrmask=`echo $iprange | grep -oE '[^/]+' | tail -1`


addipset6 () {

	if [ -z "$ipsetservers6" ]; then
		exit 0
	fi

	if [ "$protected6" = "true" ]; then
		protectedranges6
	fi

	if [ "$precheck6" = "true" ]; then
		checkipset6
	fi

	echo "Connecting to the IPSET firewalls:"

	for ipsetserver in $ipsetservers6; do
		echo -n "${ipsetserver}: "
		sudo ssh -n ${ipsetserver} "ipset -A ${ipsetname6} ${iprange} comment \"${date} ${comment}\""
		sshreturn=$?

		if [[ $sshreturn -ne 0 ]]; then
			echo -n "Error"
			echo -e
			exit 1
		else
			echo -n "Blocked"
			echo -e
		fi
	done

	echo "Done"

	exit 0
}

checkip () {

	ip=$iprange

	for server in $servers6; do
		sudo ssh -n ${server} "ip6tables -nvL ${fwchain6}" | tail -n+3 | awk {'print$7'} | grep -v "::/0" | grep -v "::1/128" | while read blockediprange;

		do
			checkaggr=$($pythonbin -q $checkaggrbin $ip $blockediprange 2>/dev/null)

			if [ ! -z "$checkaggr" ]; then
				echo "    $ip is already added in $blockediprange"
				exit 1
			fi

		done

	[[ $? != 0 ]] && exit $?

	done
}

checkipset6 () {

	echo "Checking if it's already added"

	for ipsetserver in $ipsetservers6; do
		ipsettest=$(sudo ssh -n ${ipsetserver} "ipset test ${ipsetname6} ${iprange} &>/dev/null"; echo $?)

		if [ $ipsettest = "0" ]; then
			echo "    $iprange is already added"
			exit 1
		fi
	done
}

checkpython () {

	if [ ! -f ${pythonbin} ]; then
		echo "${pythonbin} is missing, please install Python first"
		exit 1
	fi

	$pythonbin -c "import netaddr" >/dev/null 2>&1
	pmodule=$?

	if [[ $pmodule -ne 0 ]]; then
		echo "Python netaddr module is missing"
		exit 1
	fi

	if [ ! -f ${checkaggrbin} ]; then
		echo "checkaggr.py is missing, please check that it is located here as configured: ${checkaggrbin}"
		exit 1
	fi
}

protectedranges6 () {

	pip=$iprange

	for protectrange6 in $protectedranges6; do
		checkpip=$($pythonbin $checkaggrbin $pip $protectrange6)

		if [ ! -z "$checkpip" ]; then
			echo "$pip is in a protected IP range"
			exit 1
		fi
	done
}

safetylimit () {

	if [[ $cidrmask -lt $masklimit6 ]]; then
		echo "The range you want to add exceeds the current limit - a /${masklimit6} is max allowed";
		exit 1
	fi
}

validate ()  {

	if [[ ! $iprange =~ ^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) ]]; then
		echo "Invalid IPv6 address with(out) CIDR mask. Example: 2002:5bc8:c41::5bc8:0/96";
		exit 1
	fi
}


case "$1" in

add)
	validate
	safetylimit

	if [ -z "$servers6" ]; then
		addipset6
	fi

	if [ "$precheck6" = "true" ]; then
		checkpython
		checkip
	fi

	if [ "$protected6" = "true" ]; then
		checkpython
		protectedranges6
	fi

	echo "Connecting to the firewalls:"

	for server in $servers6; do
		echo -n "${server}: "
		sudo ssh -n ${server} "ip6tables -I ${fwchain6} 1 -j ${action} -s ${iprange} -m comment --comment \"${date} ${comment}\""
		sshreturn=$?

		if [[ $sshreturn -ne 0 ]]; then
			echo -n "Error"
			echo -e
			exit 1
		else
			echo -n "Blocked"
			echo -e
		fi
	done

	echo "Done"

	exit 0
	;;

del)
	validate
	ipfiltered=$iprange

	echo "Connecting to the firewalls:"

	for server in $servers6; do
		echo -n "${server}: "
		linenr=$(sudo ssh -n ${server} "ip6tables -nvL ${fwchain6} --line-numbers | grep ${ipfiltered}" | awk {'print$1'} | head -1)

		if [ -z "$linenr" ]; then
			echo -n "Not found"
			echo -e
		else
			sudo ssh -n ${server} "ip6tables -D ${fwchain6} ${linenr}"
			sshreturn=$?
			echo -n "Removed"
			echo -e
		fi

		if [[ $sshreturn -ne 0 ]]; then
			echo -n "Error"
			echo -e
			exit 1
		fi
	done

	echo "Done"

	exit 0
	;;

find)
	ipfiltered=$iprange

	echo "Connecting to the firewalls:"

	for server in $servers6; do
		echo -n "${server}: "
		echo -e
		echo " pkts bytes target     prot opt in     out     source               destination         comment"
		sudo ssh -n ${server} "ip6tables -nvL ${fwchain6} | grep -i ${ipfiltered}"
		sshreturn=$?

		if [[ $sshreturn -ne 0 ]]; then
			echo "    Not found"
			echo -e
		else
			echo -e
		fi
	done

	exit 0
	;;

findip)
	checkpython
	validate

        echo "Connecting to the firewalls:"

	ip=$iprange

        for server in $servers6; do
                echo -n "${server}: "
                echo -e
                sudo ssh -n ${server} "ip6tables -nvL ${fwchain6}" | tail -n+3 | awk {'print$7'} | grep -v "::/0" | grep -v "::1/128" | while read blockediprange;

		do
			checkaggr=$($pythonbin -q $checkaggrbin $ip $blockediprange 2> /dev/null)

			if [ ! -z "$checkaggr" ]; then
				echo "    $ip matches $blockediprange"
			fi

		done

	[[ $? != 0 ]] && exit $?

	done

        exit 0
        ;;

ipsethostinit)
        echo "Initialising $2 for IPSET use"

	sudo ssh -n $2 "ipset -N ${ipsetname6} nethash comment family inet6; ip6tables -I ${fwchain} 1 -m set --match-set ${ipsetname6} src -j ${action}"

        echo "Done"

        exit 0
        ;;

last)
	echo "Connecting to the firewalls:"

	lines=$((iprange + 2))

	for server in $servers6; do
		echo -n "${server}: "
		echo -e
		echo " pkts bytes target     prot opt in     out     source               destination         comment"
		sudo ssh -n ${server} "ip6tables -nvL ${fwchain6} | head -${lines} | tail -n+3"
		sshreturn=$?

		if [[ $sshreturn -ne 0 ]]; then
			echo "    Not found"
			echo -e
		else
			echo -e
		fi
	done

	exit 0
	;;
esac
