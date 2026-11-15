# Camera relay echo

A video-only camera publisher and an independent subscriber/player using
MoQT draft-22. Start `demo_server --moqt-relay` with a trusted certificate.
The server's exact Origin list must include `http://localhost:8080`.

Use an existing, dependency-installed [moq-web](https://github.com/Quicr/moq-web)
checkout. The tested peer revision is
`7b5c284e9166e817e7af38714ec011bc5438c710` with pnpm 9. The page bundles its
unmodified core/session sources; no CDN or copied transport codec is used.
From this directory:

```sh
node build.mjs /path/to/moq-web https://relay.example:443/moqt
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

Open `http://localhost:8080` in Chrome with:

```text
--enable-experimental-web-platform-features
--enable-features=EnableWebTransportDraft07
```

Use normal certificate validation. A process-local `--host-resolver-rules`
mapping can target a particular server while retaining the domain URL/SNI.
The relay URL can also be entered in the page or supplied as `?relay=<URL>`.
It must use HTTPS. No camera is requested until Start is clicked; no audio is
requested. Stop, permission failure and page teardown release capture.

The left window is the capture preview. The right window decodes only Objects
received by a separate MoQT subscriber through the Relay. Each returned
Group/Object identity and SHA-256 is compared with the publisher's payload.
Pause cancels the subscription and freezes the player while capture preview
continues. Resume creates a new subscription and starts a new keyframe Group.
Stop drains pending echoes and checks both WT close codes.

VP8 is configured for 640x360 at a target 15 fps and 400 kbit/s. Every encoded
frame is one Object. A keyframe starts a new Group, whose Object IDs start at
zero. These are live parameters, not a guarantee that every device sustains
that rate. Capture is skipped when encoder/send queues are busy. There is no
unbounded video history: at most 300 unmatched echoes, 600 diagnostic frame
records, 80 log entries and 8 pending send frames. Both client Sessions also
retain the peer library's resource limits.

The video payload is an example format, not LOC/MSF. Its 24-byte XQV1 header
is followed by the VP8 EncodedVideoChunk: magic `XQV1` (0..3), keyframe flag
(4), header size 24 (5), uint16 width/height (6..9), zero reserved (10..11),
uint64 microsecond timestamp (12..19), uint32 duration (20..23). All integers
are big-endian. The server forwards opaque Objects without decoding them.

## Validation

```sh
node --test packet.test.mjs
RELAY_URL=https://relay.example/moqt \
  node browser-test.mjs /path/to/moq-web /path/to/local-report
```

Optional `PAGE_URL` selects the local page origin; `MOQT_RESOLVE` accepts
`relay.example 192.0.2.1` for a Chrome-only hostname mapping. The browser
fixture uses the installed Google Chrome and its fake camera, never physical
capture. It checks echoed payload hashes, actual decoded frames, pause/resume
without local playback fallback, repeated start/stop, rejected CONNECT and
injected camera denial. Results, NetLog and screenshots stay outside Git.

Native endpoint cases 1495/1496 separately exercise namespace registration
and direct PUBLISH against the actual demo over native QUIC, WT07, WT16 and
both mixed directions. Browser success alone does not establish native MoQT
interoperability or compatibility with other media payload formats.

## HTTPS hosting

Serve the contents of `dist/` as static files over trusted HTTPS to use the
camera from a remote page. Controls and diagnostics are in English; the
capture/player heading is in Chinese. Without a
build-time or query override, the Relay URL defaults to the page's hostname
with the `/moqt` path. Add the page's exact HTTPS Origin to the Relay's
`XQC_MOQT_ALLOWED_ORIGIN` list.

A static web server can listen on TCP 443 while `demo_server --moqt-relay`
listens on UDP 443 for the same hostname. Do not advertise the MoQT-only
UDP endpoint with an HTTP `Alt-Svc` header for static page requests. Keep
certificate keys outside the static document root and disable directory
listing. Unknown static paths should return HTTP 404.

Validate the hosted page by setting `PAGE_URL=https://relay.example/` for
the browser fixture above. Its independent publish/subscribe and error
checks then run with the remote page's HTTPS Origin.
