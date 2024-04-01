.. xquic documentation master file, created by
   sphinx-quickstart on Wed Mar 13 15:45:10 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

XQUIC
=================================

XQUIC Library released by Alibaba is …

… a client and server implementation of QUIC and HTTP/3 as specified by the IETF. Currently supported QUIC versions are v1 and draft-29.

… OS and platform agnostic. It currently supports Android, iOS, Linux, macOS and Windows(v1.2.0). Most of the code is used in our own products, and has been tested at scale on android, iOS apps, as well as servers.

… still in active development. Interoperability is regularly tested with other QUIC implementations.

Feature
~~~~~~~

Standardized Features
---------------------

- All big features conforming with RFC 9000, RFC9001, RFC9002, RFC9114 and RFC9204, including the interface between QUIC and TLS, 0-RTT connection establishment, HTTP/3 and QPACK.
- ALPN Extension conforming with RFC7301


Redirection TEST
----------------
.. toctree::
   :maxdepth: 1

   quickstart
   api_refer

Requirements
~~~~~~~~~~~~
To build XQUIC, you need

- CMake
- BoringSSL or BabaSSL

To run test cases, you need

- libevent
- CUnit
