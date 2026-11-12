#!/bin/bash
# Requests and subscribed objects over real Native QUIC endpoints.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"
case_test_group "moqt.request"

case_moqt_requests()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" requests
}

case_moqt_request_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" request-errors
}

case_moqt_subscriptions()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" subscriptions
}

case_moqt_subscription_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" subscription-errors
}

case_moqt_datagrams()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" datagrams
}

case_moqt_datagram_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" datagram-errors
}

case_moqt_subgroups()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" subgroups
}

case_moqt_subgroup_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" subgroup-errors
}

case_moqt_delivery()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" delivery
}

case_test_case "moqt_delivery" --id 1450 --run case_moqt_delivery

case_moqt_delivery_cancel()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" delivery-cancel
}

case_test_case "moqt_delivery_cancel" --id 1451 --run case_moqt_delivery_cancel

case_moqt_delivery_timeout()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" delivery-timeout
}

case_test_case "moqt_delivery_timeout" --id 1470 --run case_moqt_delivery_timeout

case_test_case "moqt_subgroups" --id 1448 --run case_moqt_subgroups
case_test_case "moqt_subgroup_errors" --id 1449 --run case_moqt_subgroup_errors
case_test_case "moqt_datagrams" --id 1446 --run case_moqt_datagrams
case_test_case "moqt_datagram_errors" --id 1447 --run case_moqt_datagram_errors
case_test_case "moqt_subscriptions" --id 1444 --run case_moqt_subscriptions
case_test_case "moqt_subscription_errors" --id 1445 --run case_moqt_subscription_errors
case_test_case "moqt_requests" --id 1442 --run case_moqt_requests
case_test_case "moqt_request_errors" --id 1443 --run case_moqt_request_errors

case_moqt_fetch()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" fetch
}

case_moqt_fetch_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" fetch-errors
}

case_test_case "moqt_fetch" --id 1453 --run case_moqt_fetch
case_test_case "moqt_fetch_errors" --id 1454 --run case_moqt_fetch_errors

case_moqt_fill()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" fill
}

case_moqt_fill_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" fill-errors
}

case_test_case "moqt_fill" --id 1455 --run case_moqt_fill
case_test_case "moqt_fill_errors" --id 1456 --run case_moqt_fill_errors

case_moqt_namespaces()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" namespaces
}

case_moqt_namespace_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_negotiation" namespace-errors
}

case_test_case "moqt_namespaces" --id 1468 --run case_moqt_namespaces
case_test_case "moqt_namespace_errors" --id 1469 --run case_moqt_namespace_errors

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
