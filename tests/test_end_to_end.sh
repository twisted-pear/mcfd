#!/bin/sh

usage() {
	echo "Syntax: ${0} <mcfd> <key> <base port>"
	exit 1
}

[ ${#} -ne 3 ] && usage
[ -z "${1}" ] && usage
[ -f "${1}" -a -x "${1}" ] || usage
[ -z "${2}" ] && usage
[ -z "${3}" ] && usage
[ ${3} -le 0 -o ${3} -gt 65533 ] && usage

mcfd="${1}"
key="${2}"
clport=${3}
slport=$((${3} + 1))
scport=$((${3} + 2))

dir=`mktemp -d`

dd if=/dev/urandom of="${dir}/cin" bs=1 count=10k
dd if=/dev/urandom of="${dir}/sin" bs=1 count=10k

"${mcfd}" -k "${key}" -l 127.0.0.1 ${clport} 127.0.0.1 ${slport} > "${dir}/client.out" 2>&1 &
clientpid=${!}

"${mcfd}" -s -k "${key}" -l 127.0.0.1 ${slport} 127.0.0.1 ${scport} > "${dir}/server.out" 2>&1 &
serverpid=${!}

nc --idle-timeout=5 -l -p ${scport} < "${dir}/sin" > "${dir}/sout" &
ncserverpid=${!}

sleep 5

nc --idle-timeout=5 127.0.0.1 ${clport} < "${dir}/cin" > "${dir}/cout"

wait ${ncserverpid}

wait ${clientpid}
cexit=$?
wait ${serverpid}
sexit=$?

diff -q "${dir}/sin" "${dir}/cout"
diffa=$?
diff -q "${dir}/cin" "${dir}/sout"
diffb=$?

clsize=`stat -c "%s" "${dir}/client.out"`
slsize=`stat -c "%s" "${dir}/server.out"`

rm -r "${dir}"

[ ${cexit} -eq 0 -a ${sexit} -eq 0 -a ${diffa} -eq 0 -a ${diffb} -eq 0 -a ${clsize} -eq 0 -a ${slsize} -eq 0 ]
