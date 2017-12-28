#!/bin/bash

################################
#                              #
# Centralized Firewall Control #
#                              #
################################

if [ "$1" = "" ] || [ "$2" = "" ]; then
	echo "Usage: ./cfc.sh add n.n.n.n/NN '<optional_comment>'"
	echo "       ./cfc.sh clean <older_than_number_of_days>"
	echo "       ./cfc.sh del n.n.n.n/NN"
	echo "       ./cfc.sh ipsethostinit <server_name>"
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


addipset () {

	if [ -z "$ipsetservers" ]; then
		exit 0
	fi

	if [ "$protected" = "true" ]; then
		protectedranges
	fi

	if [ "$precheck" = "true" ]; then
		checkipset
	fi

	echo "Connecting to the IPSET firewalls:"

	for ipsetserver in $ipsetservers; do
		echo -n "${ipsetserver}: "
		sudo ssh -n ${ipsetserver} "ipset -A ${ipsetname} ${iprange} comment \"${dateipset} ${comment}\""
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

checkipset () {

	echo "Checking if it's already added"

	for ipsetserver in $ipsetservers; do
		ipsettest=$(sudo ssh -n ${ipsetserver} "ipset test ${ipsetname} ${iprange} &>/dev/null"; echo $?)

		if [ $ipsettest = "0" ]; then
			echo "    $iprange is already added"
			exit 1
		fi
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

deleterule () {

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
}

deleteipsetrule () {

	echo "Connecting to the IPSET firewalls:"

        for ipsetserver in $ipsetservers; do
                echo -n "${ipsetserver}: "
                ipsetdel=$(sudo ssh -n ${ipsetserver} "ipset del ${ipsetname} ${iprange} &>/dev/null"; echo $?)

		sshreturn=$?

                if [ $ipsetdel = "1" ]; then
                        echo -n "Not found"
                        echo -e
		fi

		if [ $ipsetdel = "0" ]; then
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
}

ipfilter () {

	ipfiltered=$(echo "$iprange" | sed -r 's/\/32//')
}

ipsetfind () {

	if [ -z "$ipsetservers" ]; then
		exit 0
	fi

	echo "Connecting to the IPSET firewalls:"

	for ipsetserver in $ipsetservers; do
		echo "${ipsetserver}: "
		sudo ssh -n ${ipsetserver} "ipset list ${ipsetname} | grep -P '(?<!\d)^\d{1,3}(?!\d)' | grep -i ${ipfiltered}"
		sshreturn=$?

		if [[ $sshreturn -ne 0 ]]; then
			echo "    Not found"
			echo -e
		else
			echo -e
		fi
	done

	exit 0
}

ipsetfindip () {

	if [ -z "$ipsetservers" ]; then
		exit 0
	fi

	echo "Connecting to the IPSET firewalls:"

	ip=$iprange
	decip=$(echo $ip | sed -r 's/\/.*//')
	binip=$(convip "${decip}")

	for ipsetserver in $ipsetservers; do
		echo -n "${ipsetserver}: "
		echo -e
		sudo ssh -n ${ipsetserver} "ipset list ${ipsetname}" | grep -P '(?<!\d)^\d{1,3}(?!\d)' | awk {'print$1'} | while read blockediprange;

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
	done

	exit 0
}

lastipset () {

        if [ -z "$ipsetservers" ]; then
                exit 0
        fi

        echo "Connecting to the IPSET firewalls:"

	lines=$iprange

	for ipsetserver in $ipsetservers; do
		echo -n "${ipsetserver}: "
		echo -e
		sudo ssh -n ${ipsetserver} "ipset list ${ipsetname} | grep -P '(?<!\d)\d{8}(?!\d)' | tr -d '\"' | sort -k7nr | head -${lines}"
		sshreturn=$?

		if [[ $sshreturn -ne 0 ]]; then
			echo "    Not found"
			echo -e
		else
			echo -e
		fi
	done

	exit 0
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

	if [ -z "$servers" ]; then
		addipset
	fi

	if [ "$protected" = "true" ]; then
		protectedranges
	fi

	if [ "$precheck" = "true" ] && [ -z "$ipsetservers" ]; then
		checkip
	else
		checkipset
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

	addipset

	;;

clean)

	if [ "$cleanupconfirmation" = "true" ]; then
		cleanupdays=$iprange
		echo "Do you really want to clean all CFC firewall rules older than ${cleanupdays} days?"
		read -r -p "[y/N] " response

		if [[ ! $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
			exit 1
		else
			cleanuptime=$((cleanupdays * 86400))
			cleanupage=0
		fi
	fi

	echo "Connecting to the firewalls:"

	for server in $servers; do
		echo -n "${server}: "
		echo -e
		sudo ssh -n ${server} "iptables -nvL ${fwchain}" | grep -P '(?<!\d)\d{8}(?!\d)' | grep -v STRING | tr -d "*" | sed -e "s/ \///g" | while read cfcrules;

		do
			cfcruledate=$(echo ${cfcrules} | awk {'print$8'})
			day=$(echo ${cfcruledate} | cut -c1-2)
			month=$(echo ${cfcruledate} | cut -c3-4)
			year=$(echo ${cfcruledate} | cut -c5-8)
			cfcruletimeunix=`date -d "$year-$month-$day" +%s`
			let cfcruleage=$(date +%s)-$(echo $cfcruletimeunix)

			if [[ $cfcruleage -gt $cleanuptime ]]; then
				ipfiltered=$(echo ${cfcrules} | awk {'print$6'})
				echo "Removing: ${ipfiltered}"
				deleterule
			fi
		done

	[[ $? != 0 ]] && exit $?

	done

	exit 0
	;;

del)
	validate
	ipfilter

	if [ -z "$servers" ]; then
		deleteipsetrule
	fi

	echo "Connecting to the firewalls:"

	deleterule

	echo "Done"

	deleteipsetrule

	exit 0
	;;

find)
	ipfilter

        if [ -z "$servers" ]; then
                ipsetfind
        fi

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

	ipsetfind

	exit 0
	;;

findip)
	validate

        if [ -z "$servers" ]; then
                ipsetfindip
        fi

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

	ipsetfindip

        exit 0
        ;;

ipsethostinit)
        echo "Initialising $2 for IPSET use"

	listtest=$(sudo ssh -n $2 "ipset -N ${ipsetname} nethash comment counters &>/dev/null"; echo $?)

	if [ $listtest = "1" ]; then
		echo "Do you want to re-create the IPSET list, all content in the current list will be deleted"
		read -r -p "[y/N] " response

		if [[ ! $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
			exit 1
		else
			linenr=$(sudo ssh -n $2 "iptables -nvL ${fwchain} --line-numbers | grep 'match-set ${ipsetname}'" | awk {'print$1'} | head -1)

			sudo ssh -n $2 "iptables -D ${fwchain} ${linenr}; ipset destroy ${ipsetname}; ipset -N ${ipsetname} nethash comment counters"
		fi
	fi

	ruletest=$(sudo ssh -n $2 "iptables -C ${fwchain} -m set --match-set ${ipsetname} src -j ${action} &>/dev/null"; echo $?)

	if [ $ruletest = "1" ]; then
		sudo ssh -n $2 "iptables -I ${fwchain} 1 -m set --match-set ${ipsetname} src -j ${action}"
	fi

        echo "Done"

        exit 0
        ;;

last)
        if [ -z "$servers" ]; then
                lastipset
        fi

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

	lastipset

	exit 0
	;;
esac
