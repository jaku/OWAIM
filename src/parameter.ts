import Fragment from './fragment.js';
import { FoodGroups as SNACFoodGroups, Types as SNACTypes } from './snac.js';
import Util from './util.js';

export enum ParameterTypes {
  UNKNOWN = -0x01,
  ONE = 0x01,
  TWO = 0x02,
  THREE = 0x03,
  FOUR = 0x04,
  FIVE = 0x05,
  SIX = 0x06,
  SEVEN = 0x07,
  EIGHT = 0x08,
  NINE = 0x09,
  TEN = 0x1a,
  TWELVE = 0x0c,
  THIRTEEN = 0x0d,
  FIFTEEN = 0x0f,
  SEVENTEEN = 0x11,
  NINETEEN = 0x13,
  THIRTY = 0x1e,
  THIRTYSEVEN = 0x25,
  EIGHTYFOUR = 0x54,
  TWOHUNDREDTHREE = 0xcb,
  TWOHUNDREDEIGHT = 0xd0,
  TWOHUNDREDNINE = 0xd1,
  TWOHUNDREDTEN = 0xd2,
  TWOHUNDREDELEVEN = 0xd3,
  TWOHUNDREDTHIRTEEN = 0xd5,
  TWOHUNDREDFOURTEEN = 0xd6,
  TWOHUNDREDFIFTEEN = 0xd7,
}

class Parameter {
  type: ParameterTypes = ParameterTypes.UNKNOWN;
  data: Buffer | Fragment[];

  constructor(a: { type: number; data: Buffer | Fragment[] }) {
    this.type = a.type;
    this.data = a.data;
  }

  public get length() {
    return this.data.length;
  }

  ToBuffer(): Buffer {
    let data: Buffer;

    if (this.data instanceof Array) {
      data = Buffer.concat(this.data.map((f) => f.ToBuffer()));
    } else {
      data = this.data;
    }
    return Buffer.concat([
      Util.Bit.ToBuffer(Util.Bit.UInt16ToBytes(this.type)),
      Util.Bit.ToBuffer(Util.Bit.UInt16ToBytes(this.length)),
      data,
    ]);
  }

  static GetParameters(snacFoodGroup: SNACFoodGroups, snacType: SNACTypes, bytes: number[]) {
    let buffer = Util.Bit.ToBuffer(bytes);
    const out: Parameter[] = [];
    while (buffer.length >= 4) {
      const type: ParameterTypes = Util.Bit.BufferToUInt16(buffer.subarray(0, 2));
      const length = Util.Bit.BufferToUInt16(buffer.subarray(2, 4));
      const payload = buffer.subarray(4, 4 + length);
      if (snacFoodGroup === SNACFoodGroups.ICBM && snacType === SNACTypes.SIX && type === ParameterTypes.TWO) {
        const fragments = Fragment.GetFragments(Util.Bit.BufferToBytes(payload));
        out.push(new Parameter({ type: type, data: fragments }));
      } else {
        out.push(new Parameter({ type: type, data: payload }));
      }

      buffer = buffer.subarray(4 + length);
    }
    return out;
  }
}

export default Parameter;
