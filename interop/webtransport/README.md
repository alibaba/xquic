# WebTransport interop image

This image runs the XQUIC `demo_client` and `demo_server` binaries, with the
interop application selected by the runner environment. Its entrypoint maps the standard
[runner environment and application contract](https://github.com/quic-interop/quic-interop-runner/blob/master/webtransport.md)
to demo arguments. It supports handshake (H) and file transfers over
unidirectional streams (UR/US), bidirectional streams (BR/BS), and datagrams
(DR/DS). Receive cases make the client request files; send cases make the
server request files from a client running `transfer`. Unsupported role/case
combinations exit 127 before simulator setup. Clients verify `/certs/ca.pem`
and the requested hostname. Application behavior and native CI are described in
[the demo documentation](../../demo/webtransport.md).
Both roles enable the demos' existing transport pacing option for the
simulator's bounded network queue; the runner's case behavior is unchanged.

Build the branch image from the XQUIC repository root:

```sh
git switch feat/webtransport
python3 interop/webtransport/test_endpoint.py
docker build --platform linux/amd64 -f interop/webtransport/Dockerfile \
    --build-arg XQUIC_REVISION="$(git rev-parse HEAD)" \
    -t xquic-webtransport-interop:local .
```

The builder runs the entrypoint tests, complete CUnit suite and focused native
WebTransport group before copying the same tested binaries into the image.
It selects the `webtransport_interop` validation profile, which links the
interop application into the normal demo binaries.

Run all seven cases from a
[runner checkout](https://github.com/quic-interop/quic-interop-runner)
with XQUIC registered:

```sh
python3 run.py -p webtransport -s xquic -c xquic \
    -r xquic=xquic-webtransport-interop:local
```

The [publication workflow](../../.github/workflows/webtransport-interop-docker.yml)
builds the checked-out `alibaba/xquic` commit and publishes
only when the workflow runs on the current `feat/webtransport` branch head.
It publishes
`ghcr.io/alibaba/xquic/xquic-webtransport-interop` with `sha-<xquic-commit>`
and `latest` tags. Only the official repository publishes this image, using
`interop/webtransport/Dockerfile`; the existing QUIC image remains at
`ghcr.io/alibaba/xquic/xquic-interop` with `interop/Dockerfile`.
The image revision label identifies the XQUIC commit; use the published
digest to reproduce an image.
Run the cross-implementation matrix locally when changing the interop demo
or image. Retain the runner matrices and endpoint logs as validation evidence,
and inspect them for `WT INTEROP FAIL` even when the runner marks a case
successful because the peer exited first. Repository CI exercises XQUIC's
native functional cases; it does not run this external matrix.
