#!/bin/bash

################################
#                              #
# Centralized Firewall Control #
#                              #
################################

if [ "$1" = "" ] || [ "$2" = "" ]; then
	echo "Usage: ./cfc.sh add n.n.n.n/NN '<optional_comment>'"
	echo "       ./cfc.sh del n.n.n.n/NN"
	echo "       ./cfc.sh find <string>"
	echo "       ./cfc.sh findip n.n.n.n/NN"
	echo "       ./cfc.sh last <nr_of_most_recent_rules>"
	exit 1
fi

# Settings
source cfc.cfg

mode=$1
iprange=$2
comment=$3
cidrmask=$(echo $iprange | grep -oE '[^/]+' | tail -1)


checkip () {

	echo "Checking if it's already added"

	ip=$iprange
	decip=$(echo $ip | sed -r 's/\/.*//')
	binip=$(convip "${decip}")

	for server in $servers; do
		sudo ssh -n ${server} "iptables -nvL ${fwchain}" | tail -n+3 | awk {'print$8'} | grep -v 0.0.0.0/0 | grep -v ! | while read blockediprange;

		do
			fblockediprange=$(echo $blockediprange | sed '/\//!s/$/\/32/g')
			cidrmaskrange=$(echo $fblockediprange | grep -oE '[^/]+' | tail -1)
			cidrmaskcmp=$(($cidrmaskrange - 1))

			decrange=$(echo $blockediprange | sed -r 's/\/.*//')
			binrange=$(convip "${decrange}")

			sigbinip=$(echo $binip | cut -c 1-"${cidrmaskcmp}")
			sigbinrange=$(echo $binrange | cut -c 1-"${cidrmaskcmp}")

			if [[ $sigbinip == $sigbinrange ]]; then
				echo "    $ip is already added in $fblockediprange"
				exit 1
			fi
		done

	[[ $? != 0 ]] && exit $?

	done
}

convip () {

        CONV=({0,1}{0,1}{0,1}{0,1}{0,1}{0,1}{0,1}{0,1})

        ip=""

        for byte in `echo ${1} | tr "." " "`; do
                ip="${ip}${CONV[${byte}]}"
        done

        echo ${ip:1}
}

ipfilter () {

	ipfiltered=$(echo "$iprange" | sed -r 's/\/32//')
}

protectedranges () {

	pip=$iprange
	decip=$(echo $pip | sed -r 's/\/.*//')
	binip=$(convip "${decip}")

	for protectrange in $protectedranges; do
		fprotectrange=$(echo $protectrange | sed '/\//!s/$/\/32/g')
		cidrmaskrange=$(echo $fprotectrange | grep -oE '[^/]+' | tail -1)
		cidrmaskcmp=$(($cidrmaskrange - 1))

		decrange=$(echo $protectrange | sed -r 's/\/.*//')
		binrange=$(convip "${decrange}")

		sigbinip=$(echo $binip | cut -c 1-"${cidrmaskcmp}")
		sigbinrange=$(echo $binrange | cut -c 1-"${cidrmaskcmp}")

		if [[ $sigbinip == $sigbinrange ]]; then
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

	if [ "$protected" = "true" ]; then
		protectedranges
	fi

	if [ "$precheck" = "true" ]; then
		checkip
	fi

	echo "Connecting to the firewalls:"

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

	echo "Connecting to the firewalls:"

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

	echo "Connecting to the firewalls:"

	for server in $servers; do
		echo -n "${server}: "
		echo -e
		echo " pkts bytes target     prot opt in     out     source               destination         comment"
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

        echo "Connecting to the firewalls:"

	ip=$iprange
	decip=$(echo $ip | sed -r 's/\/.*//')
	binip=$(convip "${decip}")

        for server in $servers; do
                echo -n "${server}: "
                echo -e
                sudo ssh -n ${server} "iptables -nvL ${fwchain}" | tail -n+3 | awk {'print$8'} | grep -v 0.0.0.0/0 | grep -v ! | while read blockediprange;

		do
			fblockediprange=$(echo $blockediprange | sed '/\//!s/$/\/32/g')
			cidrmaskrange=$(echo $fblockediprange | grep -oE '[^/]+' | tail -1)
			cidrmaskcmp=$(($cidrmaskrange - 1))

			decrange=$(echo $blockediprange | sed -r 's/\/.*//')
			binrange=$(convip "${decrange}")

			sigbinip=$(echo $binip | cut -c 1-"${cidrmaskcmp}")
			sigbinrange=$(echo $binrange | cut -c 1-"${cidrmaskcmp}")

			if [[ $sigbinip == $sigbinrange ]]; then
				echo "    $ip matches $fblockediprange"
			fi
		done

	[[ $? != 0 ]] && exit $?

	done

        exit 0
        ;;

last)
	echo "Connecting to the firewalls:"

	lines=$((iprange + 2))

	for server in $servers; do
		echo -n "${server}: "
		echo -e
		echo " pkts bytes target     prot opt in     out     source               destination         comment"
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
