#!/bin/bash

# Set up the routing needed for the simulation.
/setup.sh


if [ -n $TESTCASE ]; then
    case $TESTCASE in
        handshake|transfer|zerortt|resumption|multiconnect|http3|chacha20|keyupdate)
        :
        ;;
        *)
        exit 127
        ;;
    esac
fi


ulimit -c unlimited

LOG_DIR="/logs/"
cd xquic_bin

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 60

    # client args
    ARGS="-l d -L "$LOG_DIR/client.log" -D "/downloads" -k $SSLKEYLOGFILE -K 60"

    # zerortt
    if [ "$TESTCASE" == "zerortt" ]; then
        REQS=($REQUESTS)
        REQUESTS=${REQS[0]}
        ./interop_client $ARGS -U "$REQUESTS" -0

        REQUESTS=${REQS[@]:1}
        ./interop_client $ARGS -U "$REQUESTS" -0

    #resumption
    elif [ "$TESTCASE" == "resumption" ]; then
        REQS=($REQUESTS)
        REQUESTS=${REQS[0]}
        ./interop_client $ARGS -U "$REQUESTS"

        REQUESTS=${REQS[@]:1}
        ./interop_client $ARGS -U "$REQUESTS"

    #multiconnect
    elif [ "$TESTCASE" == "multiconnect" ]; then
        i=0
        for REQ in $REQUESTS; do
            echo "start request[$i]: $REQ"
            ./interop_client -l d -L "$LOG_DIR/client_$i.log" -D "/downloads" -k $SSLKEYLOGFILE -U "$REQ" -K 45
            i=`expr $i + 1`
        done

    # chacha20 testcase
    elif [ "$TESTCASE" == "chacha20" ]; then
        ./interop_client $ARGS -U "$REQUESTS" -S "TLS_CHACHA20_POLY1305_SHA256"

    # http3 testcase
    elif [ "$TESTCASE" == "http3" ]; then
        ./interop_client $ARGS -U "$REQUESTS" -A "h3"

    # keyupdate testcase
    elif [ "$TESTCASE" == "keyupdate" ]; then
        echo "./interop_client $ARGS -U $REQUESTS -u 30"
        ./interop_client $ARGS -U "$REQUESTS" -u 30

    # common testcase
    else
        ./interop_client $ARGS -U "$REQUESTS"
    fi

elif [ "$ROLE" == "server" ]; then
    # copy key and pem
    cp /certs/priv.key server.key
    cp /certs/cert.pem server.crt

    # start server
    ARGS="-l d -L "$LOG_DIR/server.log" -p 443 -D "/www" -k $SSLKEYLOGFILE"
    ./interop_server $ARGS
fi



#/bin/bash
