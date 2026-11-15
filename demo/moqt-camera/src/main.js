import { MOQTransport, Logger, LogLevel } from '@moq-web/core';
import { MOQTSession } from '@moq-web/session';
import { packFrame, unpackFrame } from './packet.mjs';

Logger.setLevel(LogLevel.WARN);
const $ = id => document.getElementById(id);
const WIDTH = 640, HEIGHT = 360, FPS = 15;
let stream, transport, session, encoder, decoder, captureTimer, paintTimer;
let subscriberTransport, subscriber, subscriberClose, subscriptionId;
let receiveQueue = Promise.resolve(), paused = false, changing = false;
const pendingEcho = new Map();
let sendQueue = Promise.resolve(), closePromise, pending = 0;
let active = false, closing = false, busy = false;
let forwarding = true;
let alias, namespace, group, objectId, captureCount = 0, stats;
const captureCanvas = document.createElement('canvas');
captureCanvas.width = WIDTH;
captureCanvas.height = HEIGHT;
const captureContext = captureCanvas.getContext('2d');
const decodeContext = $('decoded').getContext('2d');

function resetStats() {
    stats = { runId: Date.now().toString(36), startedAt: null, stoppedAt: null,
        state: 'idle', source: $('source').value, codec: 'vp8', draft: 'draft-22',
        width: WIDTH, height: HEIGHT, fps: FPS, encoded: 0, decoded: 0,
        sent: 0, bytes: 0, dropped: 0, errors: [], closeCode: null,
        subscriberCloseCode: null, received: 0, receivedBytes: 0,
        matched: 0, captureTicks: 0, paused: false, latencyMs: 0,
        subscribe: null, objects: [], events: [] };
    namespace = ['xquic', 'camera', stats.runId];
    group = Date.now();
    objectId = 0;
    captureCount = 0;
    pending = 0;
    sendQueue = Promise.resolve();
    receiveQueue = Promise.resolve();
    pendingEcho.clear();
    paused = changing = false;
    forwarding = true;
    $('log').textContent = '';
    const labels = { tls: 'WebTransport / 证书：等待连接',
        setup: 'MoQT SETUP：等待', publish: 'PUBLISH / REQUEST_OK：等待',
        subscribe: 'SUBSCRIBE / 播放：等待', close: '正常关闭：等待' };
    for (const id of ['tls', 'setup', 'publish', 'subscribe', 'close']) {
        $('check-' + id).className = '';
        $('check-' + id).textContent = labels[id];
    }
    $('subscribe').textContent = '暂停订阅';
    $('subscribe-result').textContent = '播放器只解码独立订阅端收到的视频对象。';
}

function log(message) {
    const event = { at: new Date().toISOString(), message };
    stats.events.push(event);
    stats.events = stats.events.slice(-80);
    $('log').textContent = stats.events.map(e =>
        `${e.at.slice(11, 23)}  ${e.message}`).join('\n');
    $('log').scrollTop = $('log').scrollHeight;
}

function step(name, message, ok = true) {
    $('check-' + name).textContent = message;
    $('check-' + name).className = ok ? 'ok' : 'error';
    log(message);
}

function state(name, label) {
    stats.state = name;
    $('state').textContent = label;
    $('state').className = 'pill ' +
        (name === 'failed' ? 'error' : ['publishing', 'stopped'].includes(name) ? 'ok' : '');
}

function controls() {
    $('start').disabled = busy || active || closing || changing;
    $('stop').disabled = !active || closing;
    $('source').disabled = busy || active || closing;
    $('relay').disabled = busy || active || closing;
    $('subscribe').disabled = !active || closing || changing;
}

function timeout(promise, ms, label) {
    let timer;
    return Promise.race([promise, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(label + '超时')), ms);
    })]).finally(() => clearTimeout(timer));
}

function releaseCapture() {
    clearInterval(captureTimer);
    clearInterval(paintTimer);
    stream?.getTracks().forEach(track => track.stop());
    stream = undefined;
    $('preview').srcObject = null;
}

function syntheticStream() {
    const canvas = document.createElement('canvas');
    canvas.width = WIDTH;
    canvas.height = HEIGHT;
    const ctx = canvas.getContext('2d');
    let frame = 0;
    function paint() {
        const x = frame++ * 5 % WIDTH;
        ctx.fillStyle = '#172e47';
        ctx.fillRect(0, 0, WIDTH, HEIGHT);
        ctx.fillStyle = '#42c6ac';
        ctx.fillRect(x - 80, 70, 120, 150);
        ctx.fillStyle = 'white';
        ctx.font = '28px monospace';
        ctx.fillText('XQUIC CAMERA TEST', 28, 40);
        ctx.font = '20px monospace';
        ctx.fillText(new Date().toISOString().slice(11, 23), 28, 320);
    }
    paint();
    paintTimer = setInterval(paint, 1000 / FPS);
    return canvas.captureStream(FPS);
}

function failure(error) {
    const message = error?.message || String(error);
    if (!stats.errors.includes(message)) stats.errors.push(message);
    log('错误：' + message);
    state('failed', '失败 · 查看日志');
    releaseCapture();
    if (active && !closing) void stop();
}

async function start() {
    if (busy || active || closing) return;
    resetStats();
    busy = true;
    controls();
    try {
        const url = new URL($('relay').value);
        if (url.protocol !== 'https:') throw new Error('Relay 必须使用 HTTPS');
        stats.relay = url.href;
        if (!globalThis.WebTransport || !globalThis.VideoEncoder
            || !globalThis.VideoDecoder) throw new Error('浏览器缺少 WT / WebCodecs 支持');
        state('capture', '等待视频权限');
        stream = $('source').value === 'test' ? syntheticStream()
            : await navigator.mediaDevices.getUserMedia({ audio: false,
                video: { width: { ideal: WIDTH }, height: { ideal: HEIGHT },
                    frameRate: { ideal: FPS, max: FPS } } });
        const track = stream.getVideoTracks()[0];
        stats.device = track.label;
        stats.audioTracks = stream.getAudioTracks().length;
        stats.cameraSettings = track.getSettings();
        $('device').textContent = track.label || '视频源已就绪';
        $('preview').srcObject = stream;
        await $('preview').play();
        const config = { codec: 'vp8', width: WIDTH, height: HEIGHT,
            bitrate: 400000, framerate: FPS, latencyMode: 'realtime' };
        if (!(await VideoEncoder.isConfigSupported(config)).supported) {
            throw new Error('此 Chrome 不支持 VP8 编码');
        }
        state('connecting', '连接 relay');
        transport = new MOQTransport({ draft: 'draft-22', connectionTimeout: 8000 });
        closePromise = new Promise(resolve => transport.on('closed', info => {
            stats.closeCode = info.closeCode;
            log(`WebTransport closed: code=${info.closeCode} ${info.reason || ''}`);
            resolve(info);
            if (active && !closing) failure(new Error('Relay 提前关闭会话'));
        }));
        await transport.connect(url.href);
        step('tls', 'WebTransport 已连接 · Chrome 正常证书校验');
        session = new MOQTSession(transport);
        session.on('error', e => { if (active && !closing) failure(e); });
        session.on('forward-state-change', ({ forward }) => {
            forwarding = forward !== 0;
            if (forwarding) captureCount = 0;
        });
        await timeout(session.setup(), 8000, 'MoQT SETUP');
        if (session.draft !== 'draft-22') throw new Error('MoQT draft 不匹配');
        step('setup', 'MoQT draft-22 SETUP 成功');
        alias = await timeout(session.publish(namespace, 'vp8', {
            deliveryMode: 'stream', priority: 128, skipForwardWait: true,
        }), 8000, 'PUBLISH');
        step('publish', `PUBLISH 成功 · REQUEST_OK · alias=${alias}`);
        $('track').textContent = namespace.join('/') + '/vp8';
        decoder = new VideoDecoder({ output: frame => {
            decodeContext.drawImage(frame, 0, 0, WIDTH, HEIGHT);
            frame.close();
            stats.decoded++;
        }, error: failure });
        decoder.configure({ codec: 'vp8', codedWidth: WIDTH, codedHeight: HEIGHT });
        subscriberTransport = new MOQTransport({ draft: 'draft-22',
            connectionTimeout: 8000 });
        subscriberClose = new Promise(resolve =>
            subscriberTransport.on('closed', info => {
                stats.subscriberCloseCode = info.closeCode;
                log(`Subscriber closed: code=${info.closeCode}`);
                resolve(info);
                if (active && !closing) failure(new Error('订阅会话提前关闭'));
            }));
        await subscriberTransport.connect(url.href);
        subscriber = new MOQTSession(subscriberTransport);
        subscriber.on('error', e => { if (active && !closing) failure(e); });
        await timeout(subscriber.setup(), 8000, '订阅端 SETUP');
        subscriptionId = await timeout(subscriber.subscribe(namespace, 'vp8',
            {}, receiveFrame), 8000, 'SUBSCRIBE');
        stats.subscribe = { status: 'accepted', subscriptionId };
        step('subscribe', 'SUBSCRIBE_OK · 播放器等待 relay 视频');
        encoder = new VideoEncoder({ output: queueChunk, error: failure });
        encoder.configure(config);
        stats.startedAt = new Date().toISOString();
        const clockStart = performance.now();
        active = true;
        state('publishing', '视频发布中');
        captureTimer = setInterval(() => {
            if (!active || closing || $('preview').readyState < 2) return;
            stats.captureTicks++;
            if (paused || !forwarding) return;
            if (pending >= 8 || encoder.encodeQueueSize >= 2) {
                stats.dropped++;
                return;
            }
            captureContext.drawImage($('preview'), 0, 0, WIDTH, HEIGHT);
            const frame = new VideoFrame(captureCanvas, {
                timestamp: Math.round((performance.now() - clockStart) * 1000),
                duration: Math.round(1000000 / FPS),
            });
            encoder.encode(frame, { keyFrame: captureCount++ % (FPS * 2) === 0 });
            frame.close();
        }, 1000 / FPS);
        log('采集 → 发布端 → relay → 独立订阅端 → 播放器');
    } catch (error) {
        failure(error);
        try { await subscriber?.close(); } catch {}
        try { await subscriberTransport?.close(); } catch {}
        try { await session?.close(); } catch {}
        try { await transport?.close(); } catch {}
        if (encoder?.state === 'configured') encoder.close();
        if (decoder?.state === 'configured') decoder.close();
        session = transport = encoder = decoder = undefined;
        subscriber = subscriberTransport = undefined;
    } finally {
        busy = false;
        controls();
        renderStats();
    }
}

function queueChunk(chunk) {
    const data = packFrame(chunk, WIDTH, HEIGHT);
    stats.encoded++;
    if (chunk.type === 'key') { group++; objectId = 0; }
    const metadata = { groupId: group, objectId: objectId++, type: 'video',
        isKeyframe: chunk.type === 'key', timestamp: chunk.timestamp };
    pending++;
    sendQueue = sendQueue.then(async () => {
        const hash = await digest(data);
        const key = metadata.groupId + '/' + metadata.objectId;
        if (pendingEcho.size >= 300) throw new Error('Relay 回传积压超过限制');
        pendingEcho.set(key, { hash, at: performance.now() });
        await session.sendObject(alias, data, metadata);
        stats.sent++;
        stats.bytes += data.length;
        if (stats.objects.length < 600) stats.objects.push({
            group: metadata.groupId, object: metadata.objectId, size: data.length,
            key: chunk.type === 'key', timestamp: chunk.timestamp,
            hash,
        });
    }).catch(failure).finally(() => pending--);
}

async function digest(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash), b =>
        b.toString(16).padStart(2, '0')).join('');
}

function receiveFrame(bytes, groupId, objectId) {
    const data = bytes.slice();
    receiveQueue = receiveQueue.then(async () => {
        const key = groupId + '/' + objectId;
        const expected = pendingEcho.get(key);
        const hash = await digest(data);
        if (!expected || expected.hash !== hash) {
            throw new Error('Relay 回传对象身份或 SHA-256 不匹配');
        }
        pendingEcho.delete(key);
        stats.received++;
        stats.receivedBytes += data.length;
        stats.matched++;
        stats.latencyMs = Math.round(performance.now() - expected.at);
        if (!paused) {
            const frame = unpackFrame(data);
            decoder.decode(new EncodedVideoChunk(frame));
        }
        if (stats.received === 1) step('subscribe', '正在播放 relay 订阅视频');
    }).catch(failure);
}

async function drainEcho() {
    const deadline = performance.now() + 6000;
    while (pendingEcho.size) {
        if (performance.now() >= deadline) throw new Error('等待 relay 回传超时');
        await new Promise(resolve => setTimeout(resolve, 20));
    }
    await receiveQueue;
}

async function stop() {
    if (closing || (!active && !session)) return;
    closing = true;
    releaseCapture();
    controls();
    try {
        if (encoder?.state === 'configured') await encoder.flush();
        await timeout(sendQueue, 6000, '发送队列');
        await drainEcho();
        if (decoder?.state === 'configured') await decoder.flush();
        await timeout(subscriber.close(), 6000, '订阅会话关闭');
        const subInfo = await timeout(subscriberClose, 6000, '订阅 WT 关闭');
        await timeout(session.close(), 6000, 'MoQT 关闭');
        const info = await timeout(closePromise, 6000, 'WT 关闭');
        const ok = info.closeCode === 0 && subInfo.closeCode === 0;
        step('close', `WT 关闭：发布=${info.closeCode} 订阅=${subInfo.closeCode}`, ok);
        if (!ok) throw new Error('WT 关闭码异常');
        stats.stoppedAt = new Date().toISOString();
        if (!stats.errors.length) state('stopped', '已正常停止');
    } catch (error) {
        failure(error);
    } finally {
        try { await subscriberTransport?.close(); } catch {}
        try { await transport?.close(); } catch {}
        if (encoder?.state === 'configured') encoder.close();
        if (decoder?.state === 'configured') decoder.close();
        active = closing = false;
        session = transport = encoder = decoder = undefined;
        subscriber = subscriberTransport = undefined;
        controls();
        renderStats();
    }
}

async function toggleSubscribe() {
    if (changing || closing || !active) return;
    changing = true;
    controls();
    try {
        if (!paused) {
            paused = true;
            await encoder.flush();
            await sendQueue;
            await drainEcho();
            await timeout(subscriber.unsubscribe(subscriptionId), 6000, '取消订阅');
            await decoder.flush();
            decoder.reset();
            decoder.configure({ codec: 'vp8', codedWidth: WIDTH, codedHeight: HEIGHT });
            stats.paused = true;
            $('subscribe').textContent = '恢复订阅';
            $('subscribe-result').textContent = '订阅已暂停；采集预览继续，播放器停止。';
            log('取消 SUBSCRIBE，播放器已暂停');
        } else {
            subscriptionId = await timeout(subscriber.subscribe(namespace, 'vp8',
                {}, receiveFrame), 8000, '恢复订阅');
            captureCount = 0;
            paused = false;
            stats.paused = false;
            $('subscribe').textContent = '暂停订阅';
            $('subscribe-result').textContent = '订阅已恢复，等待新的关键帧。';
            log('新的 SUBSCRIBE_OK，恢复 relay 视频');
        }
    } catch (error) {
        failure(error);
    } finally {
        changing = false;
        controls();
    }
}

function renderStats() {
    const end = stats.stoppedAt ? Date.parse(stats.stoppedAt) : Date.now();
    const seconds = stats.startedAt ? Math.max((end - Date.parse(stats.startedAt)) / 1000, .1) : 1;
    $('sent').textContent = stats.sent.toLocaleString();
    $('bytes').textContent = (stats.bytes / 1024).toFixed(1) + ' KB';
    $('frames').textContent = stats.encoded + ' / ' + stats.decoded;
    $('received').textContent = stats.received;
    $('matched').textContent = stats.matched;
    $('latency').textContent = stats.latencyMs + ' ms';
    $('rate').textContent = Math.round(stats.bytes * 8 / seconds / 1000) + ' kbps';
    $('dropped').textContent = stats.dropped;
}

$('start').addEventListener('click', start);
$('stop').addEventListener('click', stop);
$('subscribe').addEventListener('click', toggleSubscribe);
$('export').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(stats, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'camera-' + stats.runId + '.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});
window.addEventListener('pagehide', () => {
    releaseCapture();
    void transport?.close();
    void subscriberTransport?.close();
});
window.cameraProbe = { snapshot: () => structuredClone(stats),
    tracks: () => stream?.getTracks().map(t => ({ kind: t.kind, state: t.readyState })) || [] };
resetStats();
const query = new URLSearchParams(location.search);
$('relay').value = query.get('relay') ||
    (typeof __DEFAULT_RELAY_URL__ === 'string' ? __DEFAULT_RELAY_URL__ : '') ||
    'https://' + location.hostname + '/moqt';
setInterval(renderStats, 500);
