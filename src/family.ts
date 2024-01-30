import Util from './util.js';

class Family {
  type: number;
  version: number;

  constructor(a: { type: number; version: number }) {
    this.type = a.type;
    this.version = a.version;
  }
  ToBuffer() {
    return Util.Bit.BytesToBuffer([
      ...Util.Bit.UInt16ToBytes(this.type),
      ...(this.version ? Util.Bit.UInt16ToBytes(this.version) : []),
    ]);
  }
  static GetFamilies(bytes: number[]) {
    const buffer = Util.Bit.BytesToBuffer(bytes);
    const out: Family[] = [];
    while (buffer.length >= 4) {
      const type = Util.Bit.BufferToUInt16(buffer.subarray(0, 2));
      const version = Util.Bit.BufferToUInt16(buffer.subarray(2, 4));
      out.push(
        new Family({
          type: type,
          version: version,
        })
      );
    }
    return out;
  }
}

export default Family;
