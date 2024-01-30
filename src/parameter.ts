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
      Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(this.type)),
      Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(this.length)),
      data,
    ]);
  }

  static GetParameters(snacFoodGroup: SNACFoodGroups, snacType: SNACTypes, bytes: Buffer) {
    const out: Parameter[] = [];
    while (bytes.length >= 4) {
      const type: ParameterTypes = Util.Bit.BufferToUInt16(bytes.subarray(0, 2));
      const length = Util.Bit.BufferToUInt16(bytes.subarray(2, 4));
      const payload = bytes.subarray(4, length);
      if (snacFoodGroup === SNACFoodGroups.FOUR && snacType === SNACTypes.SIX && type === ParameterTypes.TWO) {
        const fragments = Fragment.GetFragments(payload);
        out.push(new Parameter({ type: type, data: fragments }));
      } else {
        out.push(new Parameter({ type: type, data: payload }));
      }
    }
    return out;
  }
}

export default Parameter;
