.. xquic documentation master file, created by
   sphinx-quickstart on Wed Mar 13 15:45:10 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

XQUIC's documentation
=================================

Introduction
------------
XQUIC Library released by Alibaba is …

… a client and server implementation of QUIC and HTTP/3 as specified by the IETF. Currently supported QUIC versions are v1 and draft-29.

… OS and platform agnostic. It currently supports Android, iOS, Linux, macOS and Windows(v1.2.0). Most of the code is used in our own products, and has been tested at scale on android, iOS apps, as well as servers.

… still in active development. Interoperability is regularly tested with other QUIC implementations.

Redirection TEST
----------------
.. toctree::
   :maxdepth: 1

   quickstart

Struct TEST
-----------

.. toctree::
   :maxdepth: 2

.. doxygenstruct:: xqc_scid_set_s
   :project: cid
   :members:

.. doxygenstruct:: xqc_connection_s
   :project: conn
   :members:

Fuction TEST
-------------
.. doxygenfunction:: xqc_engine_create
   :project: xquic

.. doxygenfunction:: xqc_engine_destroy
   :project: xquic

Typedef TEST
------------
.. doxygentypedef:: xqc_datagram_write_notify_pt
   :project: xquic

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

