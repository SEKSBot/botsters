// Minimal CBOR decoder — just enough for WebAuthn attestation/assertion parsing
// No dependencies. Handles maps, arrays, byte strings, text strings, integers, booleans, null.

export function decodeCBOR(data: Uint8Array): any {
  let offset = 0;

  function readUint8(): number {
    return data[offset++];
  }

  function readUint16(): number {
    const val = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    return val;
  }

  function readUint32(): number {
    const val = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    return val >>> 0;
  }

  function readBytes(n: number): Uint8Array {
    const slice = data.slice(offset, offset + n);
    offset += n;
    return slice;
  }

  function readLength(additional: number): number {
    if (additional < 24) return additional;
    if (additional === 24) return readUint8();
    if (additional === 25) return readUint16();
    if (additional === 26) return readUint32();
    throw new Error(`CBOR: unsupported length encoding ${additional}`);
  }

  function decode(): any {
    const initial = readUint8();
    const major = initial >> 5;
    const additional = initial & 0x1f;

    switch (major) {
      case 0: // unsigned integer
        return readLength(additional);
      case 1: // negative integer
        return -1 - readLength(additional);
      case 2: { // byte string
        const len = readLength(additional);
        return readBytes(len);
      }
      case 3: { // text string
        const len = readLength(additional);
        return new TextDecoder().decode(readBytes(len));
      }
      case 4: { // array
        const len = readLength(additional);
        const arr: any[] = [];
        for (let i = 0; i < len; i++) arr.push(decode());
        return arr;
      }
      case 5: { // map
        const len = readLength(additional);
        const map: Record<string | number, any> = {};
        for (let i = 0; i < len; i++) {
          const key = decode();
          map[key] = decode();
        }
        return map;
      }
      case 7: // simple values and floats
        if (additional === 20) return false;
        if (additional === 21) return true;
        if (additional === 22) return null;
        if (additional === 23) return undefined;
        throw new Error(`CBOR: unsupported simple value ${additional}`);
      default:
        throw new Error(`CBOR: unsupported major type ${major}`);
    }
  }

  return decode();
}
