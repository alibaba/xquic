#!/bin/bash

echo "Setting up routes..."
# By default, docker containers don't compute UDP / TCP checksums.
# When packets run through ns3 however, the receiving endpoint requires valid checksums.
# This command makes sure that the endpoints set the checksum on outgoing packets.
ethtool -K eth0 tx off

# this relies on the IPv4 address being first in the "hostname -I" output
IP=$(hostname -I | cut -f1 -d" ")
GATEWAY="${IP%.*}.2"
UNNEEDED_ROUTE="${IP%.*}.0"
echo "Endpoint's IPv4 address is $IP"

route add -net 193.167.0.0 netmask 255.255.0.0 gw $GATEWAY
# delete unused route
route del -net $UNNEEDED_ROUTE netmask 255.255.255.0

# this relies on the IPv6 address being second in the "hostname -I" output
IP=$(hostname -I | cut -f2 -d" ")
GATEWAY="${IP%:*}:2"
UNNEEDED_ROUTE="${IP%:*}:"
echo "Endpoint's IPv6 address is $IP"

ip -d route add fd00:cafe:cafe::/48 via $GATEWAY
# delete unused route
ip -d route del $UNNEEDED_ROUTE/64

# create the /logs and the /logs/qlog directory
mkdir -p /logs/qlog
