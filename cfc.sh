#!/bin/bash

################################
#                              #
# Centralized Firewall Control #
#                              #
################################

if [ "$1" = "" ] || [ "$2" = "" ]; then
	echo "Usage: ./cfc.sh add n.n.n.n/NN '<optional comment>'"
	echo "       ./cfc.sh del n.n.n.n/NN"
	echo "       ./cfc.sh find <string>"
	echo "       ./cfc.sh findip n.n.n.n/NN"
	echo "       ./cfc.sh last <nr_of_most_recent_rules>"
	exit 1
fi

# Settings
action=DROP
checkaggrbin=./checkaggr.py
fwchain=INPUT
masklimit=21
precheck=true
protected="172.16.0.0/12 10.0.0.0/8 192.168.0.0/16"
pythonbin=/usr/bin/python3
servers="lvs01.example.com lvs02.example.com lvs03.example.com lvs04.example.com"


mode=$1
iprange=$2
comment=$3
date=$(date +%d%m%Y)
cidrmask=`echo $iprange | grep -oE '[^/]+' | tail -1`


checkip () {

	ip=$iprange

	for server in $servers; do
		sudo ssh -n ${server} "iptables -nvL ${fwchain}" | tail -n+3 | awk {'print$8'} | grep -v 0.0.0.0/0 | grep -v ! | while read blockediprange;

		do
			checkaggr=$($pythonbin -q $checkaggrbin $ip $blockediprange 2> /dev/null)

			if [ ! -z "$checkaggr" ]; then
				echo "    $ip is already added in $blockediprange"
				exit 1
			fi

		done

	[[ $? != 0 ]] && exit $?

	done
}

ipfilter () {
	ipfiltered=`echo "$iprange" | sed -r 's/\/32//'`
}

protectedranges () {
	pip=$iprange

	for protect in $protected; do
		checkpip=$($pythonbin /usr/local/bin/checkaggr.py $pip $protect)

		if [ ! -z "$checkpip" ]; then
			echo "$pip is in a protected IP range"
			exit 1
		fi
	done
}

safetylimit () {
	if [[ $cidrmask -lt $masklimit ]]; then
		echo "The range you want to add exceeds the current limit - a /${masklimit} is max allowed";
		exit 1
	fi
}

validate ()  {
	if [[ ! $iprange =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$ ]]; then
		echo "Invalid IPv4 address with(out) CIDR mask. Example: 8.8.8.8/32";
		exit 1
	fi
}


case "$1" in

add)
	validate
	safetylimit
	protectedranges

	if [ "$precheck" = "true" ]; then
		checkip
	fi

	echo "Connecting to the loadbalancers:"

	for server in $servers; do
		echo -n "${server}: "
		sudo ssh -n ${server} "iptables -I ${fwchain} 1 -j ${action} -s ${iprange} -m comment --comment \"${date} ${comment}\""
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
	ipfilter

	echo "Connecting to the loadbalancers:"

	for server in $servers; do
		echo -n "${server}: "
		linenr=$(sudo ssh -n ${server} "iptables -nvL ${fwchain} --line-numbers | grep ${ipfiltered}" | awk {'print$1'} | head -1)

		if [ -z "$linenr" ]; then
			echo -n "Not found"
			echo -e
		else
			sudo ssh -n ${server} "iptables -D ${fwchain} ${linenr}"
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
	ipfilter

	echo "Connecting to the loadbalancers:"

	for server in $servers; do
		echo -n "${server}: "
		echo -e
		echo " pkts bytes target     prot opt in     out     source               destination        comment"
		sudo ssh -n ${server} "iptables -nvL ${fwchain} | grep -i ${ipfiltered}"
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
	validate

        echo "Connecting to the loadbalancers:"

	ip=$iprange

        for server in $servers; do
                echo -n "${server}: "
                echo -e
                sudo ssh -n ${server} "iptables -nvL ${fwchain}" | tail -n+3 | awk {'print$8'} | grep -v 0.0.0.0/0 | grep -v ! | while read blockediprange;

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

last)
	echo "Connecting to the loadbalancers:"

	lines=$((iprange + 2))

	for server in $servers; do
		echo -n "${server}: "
		echo -e
		echo " pkts bytes target     prot opt in     out     source               destination        comment"
		sudo ssh -n ${server} "iptables -nvL ${fwchain} | head -${lines} | tail -n+3"
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
