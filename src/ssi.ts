import Util from './util.js';

class SSI {
  name: string = '';
  groupId: number = -1;
  itemId: number = -1;
  classId: number = -1;
  attributes: number[] = [];

  constructor(args: { name: string; groupId: number; itemId: number; classId: number; attributes: number[] }) {
    this.name = args.name;
    this.groupId = args.groupId;
    this.itemId = args.itemId;
    this.classId = args.classId;
    this.attributes = args.attributes;
  }
  ToBuffer() {
    return Util.Bit.ToBuffer([
      ...Util.Bit.UInt16ToBytes(this.name.length),
      ...Util.Bit.StringToBytes(this.name),
      ...Util.Bit.UInt16ToBytes(this.groupId),
      ...Util.Bit.UInt16ToBytes(this.itemId),
      ...Util.Bit.UInt16ToBytes(this.classId),
      ...Util.Bit.UInt16ToBytes(this.attributes.length),
      ...this.attributes,
    ]);
  }
  static GetSSI(bytes: number[]) {
    let buffer = Util.Bit.ToBuffer(bytes);
    const out: SSI[] = [];
    while (buffer.length > 0) {
      const length = Util.Bit.BufferToUInt16(buffer.subarray(0, 2));
      const name = Util.Bit.ToString(buffer.subarray(2, length)).toString();
      const groupId = Util.Bit.BufferToUInt16(buffer.subarray(2 + length, 2));
      const itemId = Util.Bit.BufferToUInt16(buffer.subarray(4 + length, 2));
      const classId = Util.Bit.BufferToUInt16(buffer.subarray(6 + length, 2));
      const attributesLength = Util.Bit.BufferToUInt16(buffer.subarray(8 + length, 2));
      const attributes = Util.Bit.BufferToBytes(buffer.subarray(10, attributesLength));
      out.push(
        new SSI({
          name: name,
          groupId: groupId,
          itemId: itemId,
          classId: classId,
          attributes: attributes,
        })
      );
      buffer = buffer.subarray(10 + attributesLength);
    }
    return out;
  }
}

export default SSI;
