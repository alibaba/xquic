# WebTransport interop image

This image runs the existing XQUIC `wt_interop_client` and
`wt_interop_server` demos. Its entrypoint maps the standard
[runner environment and application contract](https://github.com/quic-interop/quic-interop-runner/blob/master/webtransport.md)
to demo arguments. The client supports handshake (H) and unidirectional
receive (UR); the server supports handshake and unidirectional responses.
Unsupported cases exit 127. Clients verify `/certs/ca.pem` and the requested
hostname. Application behavior and native CI are described in
[the demo documentation](../../demo/webtransport.md).

Build from the XQUIC repository root:

```sh
python3 interop/webtransport/test_endpoint.py
docker build --platform linux/amd64 -f interop/webtransport/Dockerfile \
    --build-arg XQUIC_REVISION="$(git rev-parse HEAD)" \
    -t xquic-webtransport-interop:local .
```

The builder runs the entrypoint tests, complete CUnit suite and native
WebTransport group before copying the same tested binaries into the image.

From a [runner checkout](https://github.com/quic-interop/quic-interop-runner)
with XQUIC registered:

```sh
python3 run.py -p webtransport -s xquic -c xquic \
    -t handshake,transfer-unidirectional-receive \
    -r xquic=xquic-webtransport-interop:local
```

The [publication workflow](../../.github/workflows/webtransport-interop-docker.yml)
builds the checked-out XQUIC commit and publishes
`ghcr.io/yanmei-liu/xquic-webtransport-interop` from the user fork. It requires
matching public and fork feature branches and publishes `sha-<xquic-commit>`
and `latest`. The image revision label identifies that XQUIC commit; use the
published digest to reproduce an image.
