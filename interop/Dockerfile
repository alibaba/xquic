FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends build-essential \
        git cmake golang make autoconf automake libtool \
        libevent-dev net-tools && \
    go env -w GOPROXY=https://goproxy.cn && \
    git clone --depth 1 https://github.com/alibaba/xquic.git && \
    git clone --depth 1 https://github.com/Tongsuo-Project/Tongsuo.git xquic/third_party/babassl && \
    cd xquic/third_party/babassl/ && \
    ./Configure --api=1.1.1 no-deprecated && make -j && \
    cd ../../../ && \
    mkdir xquic_bin && \
    cd xquic_bin && \
    cmake -DSSL_TYPE="babassl" \
        -DSSL_PATH="/xquic/third_party/babassl" \
        -DCMAKE_BUILD_TYPE=DEBUG \
        -DXQC_PRINT_SECRET=1 \
        -DXQC_ENABLE_TESTING=1 \
        ../xquic/ && \
    make -j && \
    rm -rf CMake* Makefile *.cmake tests xqc_configure.h test_client test_server && \
    mv demo/demo_* . && \
    cd .. && rm -rf xquic/ && \
    apt-get -y purge \
        git cmake golang make autoconf automake libtool && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]