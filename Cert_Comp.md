##源码修改了五个源文件
## tests/test_client.c
Line 204: 插入

    int g_cert_compression = 0;

Line 2939: 修改

    while ((ch = getopt(argc, argv, "a:p:P:n:c:Ct:T1s:w:r:l:Ed:u:H:h:Gx:6NMR:i:V:q:o:fe:F:D:b:B:J:QAz")) != -1) {

Line 3129: 插入

    case 'z':
        printf("cert compression using zlib :%s\n", "on");
        g_cert_compression = 1;
        break;

Line 3159: 插入

    if (g_cert_compression) {
        engine_ssl_config.cert_comp = 1;
    }

***
## tests/test_server.c
Line 111: 插入

    int g_cert_compression = 0;


Line 1440: 修改

    while ((ch = getopt(argc, argv, "a:p:ec:Cs:w:r:l:u:x:6bS:MR:o:EK:mLQz")) != -1) {

Line 1560: 插入

    case 'z':
        printf("cert compression using zlib :%s\n", "on");
        g_cert_compression = 1;
        break;

Line 1695: 插入

    if (g_cert_compression) {
        engine_ssl_config.cert_comp = 1;
    }
***
## include/xquic/xquic.h
Line 920: 插入

        int         cert_comp;


***
## src/tls/xqc_tls_ctx.c
Line 10: 插入

    #include <openssl/ssl.h>
    #include <zlib.h>

Line 37: 插入

    static int zlib_compress(SSL *s,
                         const unsigned char *in, size_t inlen,
                         unsigned char *out, size_t *outlen)
    {

        if (out == NULL) {
            *outlen = compressBound(inlen);
            return 1;
        }

        if (compress2(out, outlen, in, inlen, Z_DEFAULT_COMPRESSION) != Z_OK)
            return 0;

        return 1;
    }

    static int zlib_decompress(SSL *s,
                            const unsigned char *in, size_t inlen,
                            unsigned char *out, size_t outlen)
    {
        size_t len = outlen;

        if (uncompress(out, &len, in, inlen) != Z_OK)
            return 0;

        if (len != outlen)
            return 0;

        return 1;
    }

    typedef int (*SSL_cert_compress_cb_fn)(SSL *s,
                                       const unsigned char *in, size_t inlen,
                                       unsigned char *out, size_t *outlen);
    typedef int (*SSL_cert_decompress_cb_fn)(SSL *s,
                                            const unsigned char *in, size_t inlen,
                                            unsigned char *out, size_t outlen);

    int SSL_add_cert_compression_alg(SSL *s, int alg_id,
                                    SSL_cert_compress_cb_fn compress,
                                    SSL_cert_decompress_cb_fn decompress);

Line 369: 插入

    if (cfg->cert_comp) {
        SSL_CTX_add_cert_compression_alg(ctx->ssl_ctx, TLSEXT_cert_compression_zlib,
                                     zlib_compress, zlib_decompress);
    }

***
## CMakeLists.txt

    target_link_libraries(
            xquic-static
            z
        )

    if(PLATFORM MATCHES "mac")
        target_link_libraries(
            xquic
            "-ldl -Wl,-all_load"
            ${SSL_LIB_PATH}
            "-Wl"
            -lpthread
            z
        )
    else()
        target_link_libraries(
            xquic
            "-ldl -Wl,--whole-archive -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/scripts/xquic.lds"
            ${SSL_LIB_PATH}
            "-Wl,--no-whole-archive"
            -lpthread
            z
        )
    endif()

***
##编译时注意事项
## Install zlib
    sudo apt-get install zlib1g zlib1g-dev

***
## Build with BabaSSL
    # get and build BabaSSL
    git clone -b 8.3-stable https://github.com/Tongsuo-Project/Tongsuo.git ./third_party/babassl
    cd ./third_party/babassl/
    ./config enable-cert-compression --prefix=/usr/local/babassl
    make -j
