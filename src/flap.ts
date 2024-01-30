import Util from './util.js';

class FLAP {
  channel: number;
  sequence: number;
  size: number;
  data: Buffer;

  constructor(a: Buffer) {
    this.channel = Util.Bit.BufferToUInt8(a.subarray(1, 2));
    this.sequence = Util.Bit.BufferToUInt16(a.subarray(2, 4));
    this.size = Util.Bit.BufferToUInt16(a.subarray(4, 6));
    this.data = a.length > 6 ? a.subarray(6) : Util.Bit.BytesToBuffer([]);
  }
  ToBytes(): number[] {
    return [
      0x2a,
      ...Util.Bit.UInt8ToBytes(this.channel),
      ...Util.Bit.UInt16ToBytes(this.sequence),
      ...Util.Bit.UInt16ToBytes(this.size),
      ...this.data,
    ];
  }
}

export default FLAP;
