
Test XQUIC
==========

.. toctree::
   :maxdepth: 1
   :hidden:

   test_params


Parameter
""""""""""
To verify other features of XQUIC, you can use the additional optional parameters of test_client and test_server: :doc:`test_params`.


:Note: 
 
 The session ticket, transport parameters, and tokens may not be compatible between different servers.
 
 After using test_client to connect to one server, if you need to connect to another server, you will need to delete the ``test_session``, ``tp_localhost``, and ``xqc_token`` files saved locally by test_client;
 Otherwise, it may result in a connection failure.
 
 Additionally, different domains on the same server may be configured with different certificates.
 
 Therefore, if you want to use test_client to connect to the same server with different domain names consecutively, it is also important to note that the test_session files saved locally may cause the connection to fail.