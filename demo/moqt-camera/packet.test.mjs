import { test } from 'node:test';
import assert from 'node:assert/strict';
import { packFrame, unpackFrame } from './src/packet.mjs';

function chunk(type = 'key') {
    return { type, timestamp: 987654321, duration: 66667, byteLength: 3,
        copyTo: target => target.set([1, 2, 3]) };
}
test('preserves encoded key and delta frames including sliced buffers', () => {
    for (const type of ['key', 'delta']) {
        const packed = packFrame(chunk(type), 640, 360);
        const buffer = new Uint8Array(packed.length + 5);
        buffer.set(packed, 5);
        const frame = unpackFrame(buffer.subarray(5));
        assert.equal(frame.type, type);
        assert.equal(frame.timestamp, 987654321);
        assert.equal(frame.duration, 66667);
        assert.equal(frame.width, 640);
        assert.equal(frame.height, 360);
        assert.deepEqual([...frame.data], [1, 2, 3]);
    }
});
test('rejects truncated, unknown, oversized and invalid frame fields', () => {
    const packed = packFrame(chunk(), 640, 360);
    for (const n of [0, 4, 23, 24]) assert.throws(() => unpackFrame(packed.subarray(0, n)));
    for (const [index, value] of [[0, 0], [4, 2], [5, 23], [10, 1]]) {
        const corrupt = packed.slice();
        corrupt[index] = value;
        assert.throws(() => unpackFrame(corrupt));
    }
    assert.throws(() => packFrame(chunk(), 0, 360));
    assert.throws(() => packFrame(chunk(), 65536, 360));
    assert.throws(() => packFrame({ ...chunk(), timestamp: -1 }, 640, 360));
    assert.throws(() => packFrame({ ...chunk(), duration: 2 ** 32 }, 640, 360));
    assert.throws(() => packFrame({ ...chunk(), type: 'other' }, 640, 360));
});
