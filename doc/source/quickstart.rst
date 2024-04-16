Quick Start
===========

.. toctree::
   :maxdepth: 1
   :hidden:

   platform

Requirements
------------

The following environment should be prepared before building XQUIC.

To build XQUIC, you need

- CMake
- BoringSSL or BabaSSL

To run test cases, you need

- libevent
- CUnit


Build XQUIC
------------
XQUIC supports various systems such as ``Android`` , ``iOS`` , ``Linux`` and ``macOS``, with the default option being for ``Linux``.

On this page, we will demonstrate the compilation process on ``Linux``.

If you would like to compile on other systems, please proceed to page :doc:`platform` as needed. 

Build with BoringSSL
""""""""""""""""""""""""

.. code-block:: sh

   # get XQUIC source code
   git clone https://github.com/alibaba/xquic.git
   cd xquic

   # get and build BoringSSL
   git clone https://github.com/google/boringssl.git ./third_party/boringssl
   cd ./third_party/boringssl
   mkdir -p build && cd build
   cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
   make ssl crypto
   cd ..
   SSL_TYPE_STR="boringssl"
   SSL_PATH_STR="${PWD}"
   cd ../..
   ## Note: if you don’t have golang in your environment, please install [golang](https://go.dev/doc/install) first. 

   # build XQUIC with BoringSSL
   # When build XQUIC with boringssl, /usr/local/babassl directory will be searched
   # as default. if boringssl is deployed in other directories, SSL_PATH could be 
   # used to specify the search path of boringssl
   git submodule update --init --recursive
   mkdir -p build; cd build
   cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..

   # exit if cmake error
   if [ $? -ne 0 ]; then
      echo "cmake failed"
      exit 1
   fi

   make -j

Build with BabaSSL(Tongsuo)
"""""""""""""""""""""""""""

.. code-block:: sh
   
   # get XQUIC source code
   git clone https://github.com/alibaba/xquic.git
   cd xquic

   # get and build BabaSSL(Tongsuo)
   git clone -b 8.3-stable https://github.com/Tongsuo-Project/Tongsuo.git ./third_party/babassl
   cd ./third_party/babassl/
   ./config --prefix=/usr/local/babassl
   make -j
   SSL_TYPE_STR="babassl"
   SSL_PATH_STR="${PWD}"
   cd -

   # build XQUIC with BabaSSL
   # When build XQUIC with boringssl, /usr/local/babassl directory will be searched
   # as default. if boringssl is deployed in other directories, SSL_PATH could be 
   # used to specify the search path of boringssl
   git submodule update --init --recursive
   mkdir -p build; cd build
   cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..

   # exit if cmake error
   if [ $? -ne 0 ]; then
      echo "cmake failed"
      exit 1
   fi

   make -j


Run XQUIC
---------

After successfully building XQUIC, we can obtain ``test_client`` and ``test_server`` for testing in the ``./build`` directory.

Before running the executable files, make sure the certificates have been generated on the same directory:

.. code-block:: sh

   cd build
   keyfile=server.key
   certfile=server.crt
   openssl req -newkey rsa:2048 -x509 -nodes -keyout "$keyfile" -new -out "$certfile" -subj /CN=test.xquic.com

Then runing test_client and test_server to check if everything looks good.

.. code-block:: sh

   ./test_server -l d > /dev/null &
   ./test_client -a 127.0.0.1 -p 8443 -s 1024000 -E

Want to test XQUIC Further?
"""""""""""""""""""""""""""
Use :doc:`test_xquic` to test XQUIC features, and hopefully understand XQUIC better.