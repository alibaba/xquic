#!/bin/bash

# Set up the routing needed for the simulation.
/setup.sh

case $TESTCASE in
    versionnegotiation|handshake|longrtt|transfer|zerortt|multiconnect|chacha20|resumption|http3|retry|keyupdate|mphandshake|mptransfer|mppathabandon|mppathstatus)
        :
        ;;
    *)
        exit 127
        ;;
esac

LOG_DIR="/logs"
cd /xquic_bin/

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30

    # client args
    ARGS="-l d  -L "$LOG_DIR/client.log" -D "/downloads" -k $SSLKEYLOGFILE -K 30 -o"

    # zerortt
    if [ "$TESTCASE" == "zerortt" ]; then
        REQS=($REQUESTS)
        REQUESTS=${REQS[0]}
        ./demo_client $ARGS -U "$REQUESTS" -0

        REQUESTS=${REQS[@]:1}
        ./demo_client $ARGS -U "$REQUESTS" -0

    elif [ "$TESTCASE" == "resumption" ]; then
        REQS=($REQUESTS)
        REQUESTS=${REQS[0]}
        ./demo_client $ARGS -U "$REQUESTS"

        REQUESTS=${REQS[@]:1}
        ./demo_client $ARGS -U "$REQUESTS"

    # multiconnection testcase
    elif [ "$TESTCASE" == "multiconnect" ]; then
        i=0
        for REQ in $REQUESTS; do
            echo -e "\nstart requesty[$i]: $REQ"

            echo -e "./demo_client -l d  -L \"/logs/log_$i.log\" -D \"/downloads\" -k $SSLKEYLOGFILE -U \"$REQ\" -K 90 -o\n"
#            ./demo_client -l d  -L "/logs/log_$i.log" -D "/downloads" -k $SSLKEYLOGFILE -U "$REQ" -A "h3" -0 -K 90
            ./demo_client -l d  -L "/logs/log_$i.log" -D "/downloads" -k $SSLKEYLOGFILE -U "$REQ" -0 -K 90 -o
            i=`expr $i + 1`
        done

    # chacha20 testcase
    elif [ "$TESTCASE" == "chacha20" ]; then
        ./demo_client $ARGS -U "$REQUESTS" -S "TLS_CHACHA20_POLY1305_SHA256"

    elif [ "$TESTCASE" == "http3" ]; then
        echo "./demo_client $ARGS -U $REQUESTS -A h3"
        ./demo_client $ARGS -U "$REQUESTS" -A "h3"
    
    elif [ "$TESTCASE" == "keyupdate" ]; then
        echo "./demo_client $ARGS -U $REQUESTS -u 30"
        ./demo_client $ARGS -U "$REQUESTS" -u 30
    
    elif [ "$TESTCASE" == "mphandshake" ] || [ "$TESTCASE" == "mptransfer" ]; then
        echo "./demo_client $ARGS -U $REQUESTS -M -i eth0 -i eth0 -w 3000"
        ./demo_client $ARGS -U "$REQUESTS" -M -i eth0 -i eth0 -w 3000

    elif [ "$TESTCASE" == "mppathabandon" ]; then
        echo "./demo_client $ARGS -U $REQUESTS -M -i eth0 -i eth0 -w 3000 -Z 1000"
        ./demo_client $ARGS -U "$REQUESTS" -M -i eth0 -i eth0 -w 3000 -Z 1000
    
    elif [ "$TESTCASE" == "mppathstatus" ]; then
        echo "./demo_client $ARGS -U $REQUESTS -M -i eth0 -i eth0 -w 3000 -b"
        ./demo_client $ARGS -U "$REQUESTS" -M -i eth0 -i eth0 -w 3000 -b
    
    # common testcase
    else
        echo -e "./demo_client $ARGS -U \"$REQUESTS\"\n"

        ./demo_client $ARGS -U "$REQUESTS"
    fi

    #cp -r /downloads /logs/


elif [ "$ROLE" == "server" ]; then

    if [ "$TESTCASE" == "retry" ]; then
        exit 127
    fi

    cp /certs/priv.key server.key
    cp /certs/cert.pem server.crt
    cp server.* /logs/

    #cp -r /www /logs

    ARGS="-l d -L "$LOG_DIR/server.log" -p 443 -D "/www" -k $SSLKEYLOGFILE -i -M"
    echo "./demo_server $ARGS"
    ./demo_server $ARGS
fi
