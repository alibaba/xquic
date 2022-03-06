FROM martenseemann/quic-network-simulator-endpoint:latest

ARG CACHEBUST=1

COPY setup.sh run_endpoint.sh wait-for-it.sh ./
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends build-essential cmake golang make autoconf automake libtool libevent-dev net-tools git && \
    go env -w GOPROXY=https://goproxy.cn && \
    git clone https://github.com/Kulsk/xquic.git && \
    git clone https://github.com/BabaSSL/BabaSSL.git xquic/third_party/babassl && \
    cd xquic/third_party/babassl/ && \
    ./config --prefix=/usr/local/babassl no-sm2 no-sm3 no-sm4 && \
    make -j && \
    SSL_PATH_STR="${PWD}" && \
    SSL_INC_PATH_STR="${PWD}/include" && \
    SSL_LIB_PATH_STR="${PWD}/libssl.a;${PWD}/libcrypto.a" && \
    cd ../../../ && \
    mkdir xquic_bin && \
    cd xquic_bin && \
    cmake -DCMAKE_BUILD_TYPE=DEBUG \
        -DXQC_PRINT_SECRET=1 \
        -DXQC_ENABLE_TESTING=1 \
        CMAKE_C_FLAGS="-Werror=no-stringop-overflow, no-format-truncation, no-format-overflow"  \
        CMAKE_C_FLAGS_DEBUG="-Werror=no-stringop-overflow, no-format-truncation, no-format-overflow" \
        -DSSL_TYPE=${SSL_TYPE_STR} \
        -DSSL_PATH=${SSL_PATH_STR} \
        -DSSL_INC_PATH=${SSL_INC_PATH_STR} \
        -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} \
        ../xquic/ && \
    make -j && \
    rm -rf CMake* Makefile *.cmake tests xqc_configure.h test_client test_server && \
    rm -rf /var/log/* && \
    cd .. && rm -rf xquic/ && \
    apt-get -y purge cmake golang make autoconf automake libtool && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/* && \
    chmod +x setup.sh run_endpoint.sh wait-for-it.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
