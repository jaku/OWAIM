import Util from './util.js';

class Fragment {
  id: number = -1;
  version: number;
  length: number = 0;
  data: Buffer;

  constructor(a: { id: number; version: number; length: number; data: Buffer }) {
    this.id = a.id;
    this.version = a.version;
    this.data = a.data;
  }

  ToBuffer() {
    return Util.Bit.ToBuffer([
      ...Util.Bit.UInt8ToBytes(this.id),
      ...Util.Bit.UInt8ToBytes(this.version),
      ...Util.Bit.UInt16ToBytes(this.data.length),
      ...Util.Bit.BufferToBytes(this.data),
    ]);
  }

  static GetFragments(bytes: number[]): Fragment[] {
    const buffer = Util.Bit.ToBuffer(bytes);
    const out: Fragment[] = [];
    let bufferPosition = 0;
    while (buffer.length >= 4) {
      const fragId = Util.Bit.BufferToUInt8(buffer, bufferPosition);
      bufferPosition += 1;
      const fragVersion = Util.Bit.BufferToUInt8(buffer, bufferPosition);
      bufferPosition += 1;
      const length = Util.Bit.BufferToUInt16(buffer, bufferPosition);
      bufferPosition += 2;
      const payload = Util.Bit.ToBuffer(buffer, bufferPosition, length);
      bufferPosition += length;

      out.push(
        new Fragment({
          id: fragId,
          version: fragVersion,
          length: length,
          data: payload,
        })
      );
    }

    return out;
  }
}

export default Fragment;
