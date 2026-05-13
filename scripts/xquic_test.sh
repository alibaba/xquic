#!/bin/bash
# Copyright (c) 2022, Alibaba Group Holding Limited

set -e

#######################################
# Detect distro and package manager
#######################################
if [ -f /etc/os-release ]; then
    . /etc/os-release
else
    echo "Cannot detect OS distribution"
    exit 1
fi

PKG_MGR=""
INSTALL_CMD=""

case "$ID" in
    ubuntu|debian)
        PKG_MGR="apt"
        INSTALL_CMD="apt install -y"
        ;;
    rhel|centos|almalinux|rocky|ol)
        PKG_MGR="yum"
        INSTALL_CMD="yum install -y"
        ;;
    *)
        if echo "$ID_LIKE" | grep -q "rhel\|fedora"; then
            PKG_MGR="yum"
            INSTALL_CMD="yum install -y"
        elif echo "$ID_LIKE" | grep -q "debian"; then
            PKG_MGR="apt"
            INSTALL_CMD="apt install -y"
        else
            echo "Unsupported distro: $ID"
            exit 1
        fi
        ;;
esac

echo "Detected distro:  $ID (using $PKG_MGR)"

#######################################
# Install dependencies
#######################################
echo ""
echo "=== Installing Dependencies ==="

if [ "$PKG_MGR" = "yum" ]; then
    sudo yum install -y gcc gcc-c++ make cmake git openssl-devel pkgconfig psmisc
    sudo yum install -y python3-pip python3-lxml
    sudo pip3 install gcovr
    sudo yum install -y CUnit CUnit-devel
    sudo yum install -y golang
else
    sudo apt update -y
    sudo apt install -y build-essential cmake git openssl libssl-dev pkg-config psmisc
    sudo add-apt-repository -y universe 2>/dev/null || true
    sudo apt update -y
    sudo apt install -y python3-pip python3-lxml gcovr
    sudo apt install -y libcunit1-dev
    sudo apt install -y golang-go
fi

echo "✓ Dependencies installed"

#######################################
# Detect SSL backend
#######################################
echo ""
echo "=== Detecting SSL Backend ==="

SSL_TYPE_STR=""
SSL_PATH_STR=""

# Check for BoringSSL
if [ -f "../third_party/boringssl/build/libssl.a" ]; then
    SSL_TYPE_STR="boringssl"
    SSL_PATH_STR="$(cd ../third_party/boringssl && pwd)"
    echo "✓ Found BoringSSL at: $SSL_PATH_STR"
elif [ -f "../third_party/boringssl/build/ssl/libssl.a" ]; then
    SSL_TYPE_STR="boringssl"
    SSL_PATH_STR="$(cd ../third_party/boringssl && pwd)"
    echo "✓ Found BoringSSL at: $SSL_PATH_STR"
# Check for BabaSSL
elif [ -f "../third_party/babassl/libssl.a" ]; then
    SSL_TYPE_STR="babassl"
    SSL_PATH_STR="$(cd ../third_party/babassl && pwd)"
    echo "✓ Found BabaSSL at:  $SSL_PATH_STR"
elif [ -f "/usr/local/babassl/lib/libssl.a" ]; then
    SSL_TYPE_STR="babassl"
    SSL_PATH_STR="/usr/local/babassl"
    echo "✓ Found BabaSSL at: $SSL_PATH_STR"
else
    echo "✗ No SSL backend found"
    exit 1
fi

#######################################
# Check XQUIC build
#######################################
echo ""
echo "=== Checking XQUIC Build ==="

if [ !  -f "./libxquic.so" ]; then
    echo "✗ XQUIC not built yet"
    exit 1
fi

echo "✓ XQUIC library found"

if [ ! -f "./tests/run_tests" ]; then
    echo "✗ Test binaries not found"
    exit 1
fi

echo "✓ Test binaries found"
echo "✓ Using SSL backend: $SSL_TYPE_STR at $SSL_PATH_STR"

#######################################
# Generate certificates
#######################################
echo ""
echo "=== Generating Certificates ==="

if [ ! -f "server.key" ] || [ ! -f "server.crt" ]; then
    openssl req -newkey rsa:2048 -x509 -nodes \
        -keyout server.key \
        -out server.crt \
        -subj /CN=test.xquic.com
    echo "✓ Certificates generated"
else
    echo "✓ Certificates already exist"
fi

#######################################
# Run tests
#######################################
echo ""
echo "=== Running Tests ==="

# Clear previous test log
> xquic_test.log

echo "Running unit tests..."
./tests/run_tests | tee -a xquic_test.log

echo "Running case tests..."
bash ../scripts/case_test.sh | tee -a xquic_test.log

#######################################
# Generate coverage
#######################################
echo ""
echo "=== Generating Coverage Report ==="
gcovr -r ..  | tee -a xquic_test.log

#######################################
# Summary
#######################################
echo ""
echo "=============Summary=============="

echo ""
echo "Unit Tests:"
grep "Test:" xquic_test.log || true
passed=$(grep "Test:" xquic_test.log | grep -c "passed" || true)
failed=$(grep "Test:" xquic_test.log | grep -c "FAILED" || true)
echo "  Passed: $passed | Failed:  $failed"

echo ""
echo "Case Tests:"
grep "pass:" xquic_test.log || true
passed=$(grep "pass:" xquic_test.log | grep -c "pass:  1" || true)
failed=$(grep "pass:" xquic_test.log | grep -c "pass: 0" || true)
echo "  Passed: $passed | Failed:  $failed"

echo ""
echo "Code Coverage:"
grep "TOTAL" xquic_test.log || true

echo ""
echo "=================================="
echo "Full log saved to: build/xquic_test.log"

cd -
