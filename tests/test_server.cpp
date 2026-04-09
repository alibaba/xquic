// test_server.cpp
#include "xquic_server.h"
#include <stdio.h>


int main(int argc, char *argv[]) {
    XquicServer server;
    return server.start(argc, argv);
}