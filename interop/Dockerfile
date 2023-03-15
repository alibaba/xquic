FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends build-essential cmake golang make autoconf automake libtool libevent-dev net-tools git && \
    go env -w GOPROXY=https://goproxy.cn && \
    git clone --depth 1 https://github.com/alibaba/xquic.git && \
    git clone --depth 1 https://github.com/google/boringssl.git xquic/third_party/boringssl && \
    cd xquic/third_party/boringssl/ && \
    if [ ! -d build ]; then mkdir build; else rm -rf build; mkdir build; fi && \
    cd build && \
    cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" .. && \
    make ssl crypto && \
    cd ../../../../ && \
    mkdir xquic_bin && \
    cd xquic_bin && \
    cmake -DXQC_OPENSSL_IS_BORINGSSL=1 \
        -DCMAKE_BUILD_TYPE=DEBUG \
        -DXQC_PRINT_SECRET=1 \
        -DXQC_ENABLE_TESTING=1 \
        CMAKE_C_FLAGS="-Werror=no-stringop-overflow, no-format-truncation, no-format-overflow"  \
        CMAKE_C_FLAGS_DEBUG="-Werror=no-stringop-overflow, no-format-truncation, no-format-overflow" \
        LDFLAGS="-Wl,-rpath,./" \
        ../xquic/ && \
    make -j && \
    rm -rf CMake* Makefile *.cmake tests xqc_configure.h test_client test_server && \
    rm -rf /var/log/* && \
    cd .. && rm -rf xquic/ && \
    apt-get -y purge cmake golang make autoconf automake libtool && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]