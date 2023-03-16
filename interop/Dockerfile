FROM martenseemann/quic-network-simulator-endpoint:latest

ENV XQC_PATH /xquic \
    SSL_PATH $XQC_PATH/third_party/boringssl \
    SSL_INC_PATH $SSL_PATH/include \
    SSL_LIB_PATH $SSL_PATH/build/ssl/libssl.a;$SSL_PATH/build/crypto/libcrypto.a

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends build-essential \
        git cmake golang make autoconf automake libtool \
        libevent-dev net-tools && \
    go env -w GOPROXY=https://goproxy.cn && \
    git clone --depth 1 --branch interop https://github.com/alibaba/xquic.git && \
    git clone --depth 1 https://github.com/google/boringssl.git xquic/third_party/boringssl && \
    cd xquic/third_party/boringssl/ && \
    if [ ! -d build ]; then mkdir build; else rm -rf build; mkdir build; fi && \
    cd build && \
    cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" .. && \
    make ssl crypto && \
    cd ../../../../ && \
    mkdir xquic_bin && \
    cd xquic_bin && \
    cmake -DSSL_TYPE="boringssl" \
        -DSSL_PATH="$SSL_PATH" \
        -DSSL_INC_PATH="$SSL_INC_PATH" \
        -DSSL_LIB_PATH="$SSL_LIB_PATH" \
        -DCMAKE_BUILD_TYPE=DEBUG \
        -DXQC_PRINT_SECRET=1 \
        -DXQC_ENABLE_TESTING=1 \
        ../xquic/ && \
    make -j && \
    rm -rf CMake* Makefile *.cmake tests xqc_configure.h test_client test_server && \
    cd .. && rm -rf xquic/ && \
    apt-get -y purge \
        git cmake golang make autoconf automake libtool && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]