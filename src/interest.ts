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
    const buffer = Util.Bit.ToBuffer(bytes);
    const out: Interest[] = [];

    let bufferPosition = 0;
    while (buffer.length > 4) {
      const type = Util.Bit.BufferToUInt8(buffer, bufferPosition);
      bufferPosition += 1;
      const id = Util.Bit.BufferToUInt8(buffer, bufferPosition);
      bufferPosition += 1;
      const length = Util.Bit.BufferToUInt16(buffer, bufferPosition);
      bufferPosition += 2;
      const name = Util.Bit.ToString(buffer, bufferPosition, length);
      bufferPosition += length;

      out.push(
        new Interest({
          type: type,
          id: id,
          length: length,
          name: name,
        })
      );
    }
    return out;
  }
}

export default Interest;
