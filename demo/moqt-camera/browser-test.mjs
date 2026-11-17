import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const moq = process.argv[2] && path.resolve(process.argv[2]);
if (!moq) throw new Error('Usage: node browser-test.mjs /path/moq-web [report-dir]');
const output = path.resolve(process.argv[3] || path.join(root, 'build/report'));
await fs.mkdir(output, { recursive: true });
const { chromium } = await import(path.join(moq,
    'packages/session-e2e/node_modules/playwright/index.mjs'));
const args = ['--enable-experimental-web-platform-features',
    '--enable-features=EnableWebTransportDraft07',
    '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream',
    `--log-net-log=${output}/chrome-netlog.json`];
if (process.env.MOQT_RESOLVE) {
    args.push('--host-resolver-rules=MAP ' + process.env.MOQT_RESOLVE);
}
const url = new URL(process.env.PAGE_URL || 'http://localhost:8080');
if (process.env.RELAY_URL) url.searchParams.set('relay', process.env.RELAY_URL);
const result = { startedAt: new Date().toISOString(), cases: [],
    tlsBypass: false, camera: 'Chrome fake device, no physical capture' };
const browser = await chromium.launch({ channel: 'chrome', headless: false, args });
result.chrome = browser.version();
const context = await browser.newContext({ viewport: { width: 1280, height: 1120 } });
const page = await context.newPage();
const logs = [];
page.on('console', message => logs.push(message.type() + ': ' + message.text()));
page.on('pageerror', error => logs.push('PAGEERROR: ' + error.stack));
const snapshot = () => page.evaluate(() => window.cameraProbe.snapshot());
async function begin(source = 'camera') {
    await page.selectOption('#source', source);
    await page.click('#start');
    await page.waitForFunction(() => ['publishing', 'failed'].includes(
        window.cameraProbe.snapshot().state), null, { timeout: 25000 });
    const s = await snapshot();
    assert.equal(s.state, 'publishing', JSON.stringify(s));
    assert.equal(s.audioTracks, 0);
    assert.equal(s.subscribe.status, 'accepted');
}
async function stop() {
    await page.click('#stop');
    await page.waitForFunction(() => ['stopped', 'failed'].includes(
        window.cameraProbe.snapshot().state), null, { timeout: 20000 });
    const s = await snapshot();
    assert.equal(s.state, 'stopped', JSON.stringify(s));
    assert.equal(s.closeCode, 0);
    assert.equal(s.subscriberCloseCode, 0);
    assert.deepEqual(s.errors, []);
    assert.deepEqual(await page.evaluate(() => window.cameraProbe.tracks()), []);
    assert.equal(s.sent, s.received);
    assert.equal(s.bytes, s.receivedBytes);
    assert.equal(s.matched, s.received);
    return s;
}

try {
    await page.goto(url.href);
    await page.waitForFunction(() => !!window.cameraProbe);
    await begin();
    await page.waitForFunction(() => window.cameraProbe.snapshot().decoded >= 150,
        null, { timeout: 30000 });
    await page.screenshot({ path: output + '/echo-live.png', fullPage: true });
    let s = await stop();
    assert.equal(s.encoded, s.sent);
    assert.equal(s.decoded, s.received);
    await fs.writeFile(output + '/echo-session.json', JSON.stringify(s, null, 2));
    result.cases.push({ name: 'camera-relay-subscribe-play-close', passed: true,
        frames: s.decoded, matched: s.matched, bytes: s.receivedBytes,
        close: [s.closeCode, s.subscriberCloseCode] });
    await page.screenshot({ path: output + '/echo-stopped.png', fullPage: true });

    await begin('test');
    await page.waitForFunction(() => window.cameraProbe.snapshot().decoded >= 30,
        null, { timeout: 12000 });
    await page.click('#subscribe');
    await page.waitForFunction(() => window.cameraProbe.snapshot().paused,
        null, { timeout: 10000 });
    const before = await snapshot();
    const frozenPixels = await page.locator('#decoded').evaluate(c => c.toDataURL());
    const captureTime = await page.locator('#preview').evaluate(v => v.currentTime);
    await page.waitForFunction(n => window.cameraProbe.snapshot().captureTicks > n + 20,
        before.captureTicks, { timeout: 6000 });
    const frozen = await snapshot();
    assert.equal(frozen.decoded, before.decoded);
    assert.equal(frozen.received, before.received);
    assert.equal(await page.locator('#decoded').evaluate(c => c.toDataURL()),
        frozenPixels);
    assert.ok(await page.locator('#preview').evaluate(v => v.currentTime) >
        captureTime + 0.5);
    await page.click('#subscribe');
    await page.waitForFunction(n => window.cameraProbe.snapshot().decoded > n + 30,
        before.decoded, { timeout: 12000 });
    s = await stop();
    await fs.writeFile(output + '/pause-session.json', JSON.stringify(s, null, 2));
    result.cases.push({ name: 'subscription-pause-freezes-player-resume-restarts',
        passed: true, frozenAt: before.decoded, afterResume: s.decoded,
        captureContinued: frozen.captureTicks - before.captureTicks });

    const bad = new URL(s.relay);
    bad.pathname = '/not-moqt';
    await page.fill('#relay', bad.href);
    await page.click('#start');
    await page.waitForFunction(() => window.cameraProbe.snapshot().state === 'failed',
        null, { timeout: 15000 });
    await page.waitForFunction(() => !document.querySelector('#start').disabled);
    s = await snapshot();
    assert.equal(s.sent, 0);
    assert.deepEqual(await page.evaluate(() => window.cameraProbe.tracks()), []);
    result.cases.push({ name: 'wrong-path-rejected-and-capture-released', passed: true });

    await page.addInitScript(() => {
        navigator.mediaDevices.getUserMedia = async () => {
            throw new DOMException('Injected camera denial', 'NotAllowedError');
        };
    });
    await page.goto(url.href);
    await page.waitForFunction(() => !!window.cameraProbe);
    await page.click('#start');
    await page.waitForFunction(() => window.cameraProbe.snapshot().state === 'failed');
    s = await snapshot();
    assert.ok(s.errors.includes('Injected camera denial'));
    assert.equal(s.sent, 0);
    assert.deepEqual(await page.evaluate(() => window.cameraProbe.tracks()), []);
    result.cases.push({ name: 'injected-camera-denial-reported', passed: true });
    assert.ok(!logs.some(line => line.startsWith('PAGEERROR:')), logs.join('\n'));
    result.passed = result.cases.length;
} catch (error) {
    result.error = error.stack;
    result.snapshot = await snapshot().catch(() => null);
    await page.screenshot({ path: output + '/failure.png', fullPage: true }).catch(() => {});
    process.exitCode = 1;
} finally {
    result.finishedAt = new Date().toISOString();
    await fs.writeFile(output + '/result.json', JSON.stringify(result, null, 2));
    await fs.writeFile(output + '/console.log', logs.slice(-1000).join('\n'));
    await browser.close();
    console.log(JSON.stringify(result, null, 2));
}
