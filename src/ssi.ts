import Util from './util.js';

class SSI {
  name: string = '';
  groupId: number = -1;
  itemId: number = -1;
  classId: number = -1;
  attributes: number[] = [];

  constructor(a: { name: string; groupId: number; itemId: number; classId: number; attributes: number[] }) {
    this.name = a.name;
    this.groupId = a.groupId;
    this.itemId = a.itemId;
    this.classId = a.classId;
    this.attributes = a.attributes;
  }
  ToBuffer() {
    return Util.Bit.BytesToBuffer([
      ...Util.Bit.UInt16ToBytes(this.name.length),
      ...Util.Bit.StringToBytes(this.name),
      ...Util.Bit.UInt16ToBytes(this.groupId),
      ...Util.Bit.UInt16ToBytes(this.itemId),
      ...Util.Bit.UInt16ToBytes(this.classId),
      ...Util.Bit.UInt16ToBytes(this.attributes.length),
      ...this.attributes,
    ]);
  }
  static GetSSI(bytes) {
    var _buffer = [...bytes];
    var out = [];
    while (_buffer.length > 0) {
      let length = Util.Bit.BufferToUInt16(_buffer.splice(0, 2));
      let name = Util.Bit.BytesToBuffer(_buffer.splice(0, length)).toString('ascii');
      let groupId = Util.Bit.BufferToUInt16(_buffer.splice(0, 2));
      let itemId = Util.Bit.BufferToUInt16(_buffer.splice(0, 2));
      let classId = Util.Bit.BufferToUInt16(_buffer.splice(0, 2));
      let attributesLength = Util.Bit.BufferToUInt16(_buffer.splice(0, 2));
      let attributes = _buffer.splice(0, attributesLength);
      out.push(
        new SSI({
          name: name,
          groupId: groupId,
          itemId: itemId,
          classId: classId,
          attributes: attributes,
        })
      );
    }
    return out;
  }
}

export default SSI;
