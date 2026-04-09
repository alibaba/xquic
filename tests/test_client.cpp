// test_client.cpp
#include "xquic_client.h"
#include <stdio.h>

/*
 * Thin C++ main that instantiates XquicClient and runs it.
 * All logic has been moved into the XquicClient class.
 */
int main(int argc, char *argv[]) {
    XquicClient client;
    return client.start(argc, argv);
}