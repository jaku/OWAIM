import Util from './util.js';

class Interest {
  type: number;
  id: number;
  name: string;

  constructor(a: { type: number; id: number; length: number; name: string }) {
    this.type = a.type;
    this.id = a.id;
    this.name = a.name;
  }
  ToBytes(): number[] {
    return [
      ...Util.Bit.UInt8ToBytes(this.type),
      ...Util.Bit.UInt8ToBytes(this.id),
      ...Util.Bit.UInt16ToBytes(this.name.length),
      ...Util.Bit.StringToBytes(this.name),
    ];
  }
  static GetInterests(bytes: number[]) {
    let buffer = Util.Bit.ToBuffer(bytes);
    const out: Interest[] = [];
    while (buffer.length > 4) {
      const type = Util.Bit.BufferToUInt8(buffer.subarray(0, 1));
      const id = Util.Bit.BufferToUInt8(buffer.subarray(1, 2));
      const length = Util.Bit.BufferToUInt16(buffer.subarray(2, 4));
      const name = Util.Bit.ToString(buffer.subarray(4, 4 + length));
      out.push(
        new Interest({
          type: type,
          id: id,
          length: length,
          name: name,
        })
      );
      buffer = buffer.subarray(4 + length);
    }
    return out;
  }
}

export default Interest;
