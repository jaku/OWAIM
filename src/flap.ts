import Util from './util.js';

class FLAP {
  channel: number;
  sequence: number;
  size: number;
  data: Buffer;

  constructor(channel: number, sequence: number, size: number, data: number[]) {
    this.channel = channel;
    this.sequence = sequence;
    this.size = size;
    this.data = Util.Bit.ToBuffer(data);
  }
  ToBuffer() {
    return Util.Bit.ToBuffer([
      0x2a,
      ...Util.Bit.UInt8ToBytes(this.channel),
      ...Util.Bit.UInt16ToBytes(this.sequence),
      ...Util.Bit.UInt16ToBytes(this.size),
      ...Util.Bit.BufferToBytes(this.data),
    ]);
  }
}

export default FLAP;
