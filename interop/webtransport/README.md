# WebTransport interop image

This image runs the existing XQUIC `wt_interop_client` and
`wt_interop_server` demos. Its entrypoint maps the standard
[runner environment and application contract](https://github.com/quic-interop/quic-interop-runner/blob/master/webtransport.md)
to demo arguments. It supports handshake (H) and file transfers over
unidirectional streams (UR/US), bidirectional streams (BR/BS), and datagrams
(DR/DS). Receive cases make the client request files; send cases make the
server request files from a client running `transfer`. Unsupported role/case
combinations exit 127 before simulator setup. Clients verify `/certs/ca.pem`
and the requested hostname. Application behavior and native CI are described in
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

Run all seven cases from a
[runner checkout](https://github.com/quic-interop/quic-interop-runner)
with XQUIC registered:

```sh
python3 run.py -p webtransport -s xquic -c xquic \
    -r xquic=xquic-webtransport-interop:local
```

The [publication workflow](../../.github/workflows/webtransport-interop-docker.yml)
builds the checked-out XQUIC commit and publishes
`ghcr.io/yanmei-liu/xquic-webtransport-interop` from the user fork. It requires
matching public and fork feature branches and publishes `sha-<xquic-commit>`
and `latest`. The image revision label identifies that XQUIC commit; use the
published digest to reproduce an image.
