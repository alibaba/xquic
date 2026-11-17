const HEADER_SIZE = 24;
const MAGIC = [0x58, 0x51, 0x56, 0x31];

export function packFrame(chunk, width, height) {
    if (![width, height].every(n => Number.isInteger(n) && n > 0 && n <= 65535)
        || !Number.isSafeInteger(chunk.timestamp) || chunk.timestamp < 0
        || !Number.isInteger(chunk.byteLength) || chunk.byteLength <= 0
        || !['key', 'delta'].includes(chunk.type)) {
        throw new Error('Invalid video frame');
    }
    const duration = chunk.duration ?? 0;
    if (!Number.isInteger(duration) || duration < 0 || duration > 0xffffffff) {
        throw new Error('Invalid duration');
    }
    const data = new Uint8Array(HEADER_SIZE + chunk.byteLength);
    const view = new DataView(data.buffer);
    data.set(MAGIC);
    view.setUint8(4, chunk.type === 'key' ? 1 : 0);
    view.setUint8(5, HEADER_SIZE);
    view.setUint16(6, width);
    view.setUint16(8, height);
    view.setBigUint64(12, BigInt(chunk.timestamp));
    view.setUint32(20, duration);
    chunk.copyTo(data.subarray(HEADER_SIZE));
    return data;
}

export function unpackFrame(data) {
    if (!(data instanceof Uint8Array) || data.length <= HEADER_SIZE
        || MAGIC.some((b, i) => data[i] !== b)
        || data[4] > 1 || data[5] !== HEADER_SIZE) {
        throw new Error('Invalid XQV1 envelope');
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const timestamp = view.getBigUint64(12);
    const width = view.getUint16(6), height = view.getUint16(8);
    if (!width || !height || timestamp > BigInt(Number.MAX_SAFE_INTEGER)
        || view.getUint16(10) !== 0) {
        throw new Error('Invalid XQV1 fields');
    }
    return { type: data[4] ? 'key' : 'delta', timestamp: Number(timestamp),
        duration: view.getUint32(20), width, height,
        data: data.subarray(HEADER_SIZE) };
}
