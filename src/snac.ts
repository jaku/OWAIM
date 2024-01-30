import extend from 'extend';
import Family from './family.js';
import Interest from './interest.js';
import Parameter, { ParameterTypes } from './parameter.js';
import SSI from './ssi.js';
import Util from './util.js';

export const enum FoodGroups {
  ZERO = 0x00,
  ONE = 0x01,
  TWO = 0x02,
  THREE = 0x03,
  FOUR = 0x04,
  FIVE = 0x05,
  SIX = 0x06,
  SEVEN = 0x07,
  EIGHT = 0x08,
  NINE = 0x09,
  TEN = 0x0a,
  ELEVEN = 0x0b,
  TWELVE = 0x0c,
  THIRTEEN = 0x0d,
  FOURTEEN = 0x0e,
  FIFTEEN = 0x0f,
  SIXTEEN = 0x10,
  NINETEEN = 0x13,
  TWENTYONE = 0x15,
  TWENTYTHREE = 0x17,
  TWENTYFOUR = 0x18,
}
export const enum Types {
  ZERO = 0x00,
  ONE = 0x01,
  TWO = 0x02,
  THREE = 0x03,
  FOUR = 0x04,
  FIVE = 0x05,
  SIX = 0x06,
  SEVEN = 0x07,
  EIGHT = 0x08,
  NINE = 0x09,
  TEN = 0x0a,
  ELEVEN = 0x0b,
  TWELVE = 0x0c,
  FOURTEEN = 0x0e,
  FIFTEEN = 0x0f,
  SEVENTEEN = 0x11,
  EIGHTEEN = 0x12,
  TWENTYONE = 0x15,
  TWENTYTHREE = 0x17,
  TWENTYFOUR = 0x18,
  THIRTY = 0x1e,
}

class SNAC {
  foodGroup: FoodGroups = FoodGroups.ZERO;
  type: Types = Types.ZERO;
  flags: number = 0;
  requestId: number = 0;
  parameters: Parameter[] = [];
  count: number = 0;
  date: Date = new Date();
  cookie: string = '';
  authKey: string = '';
  formattedScreenName: string = '';
  interests: Interest[] = [];
  families: Family[] = [];
  channel: number = -1;
  errorId: number = -1;
  permissions: number = 0;
  groupId: number = -1;
  screenName: string = '';
  requestFlags: number[] = [];
  warningLevel: number = 0;
  idle: number = 0;
  groups: number[] = [];
  items: SSI[] = [];
  autoResponse?: Parameter;
  instance: number = -1;
  detailLevel: number = 0;
  exchange: number = -1;

  constructor(
    arg:
      | {
          extensions?: unknown;
          length?: number;
          foodGroup: FoodGroups;
          type: Types;
          flags: number;
          requestId: number;
          parameters?: Parameter[];
        }
      | Buffer
  ) {
    if (!arg) {
      return;
    } else if (arg instanceof Buffer) {
      const packet = arg.subarray(0, 10);
      this.foodGroup = Util.Bit.BufferToUInt16(packet.subarray(0, 2));
      this.type = Util.Bit.BufferToUInt16(packet.subarray(2, 4));
      this.flags = Util.Bit.BufferToUInt16(packet.subarray(4, 6));
      this.requestId = Util.Bit.BufferToUInt32(packet.subarray(6, 10));
      if (arg.length > 10) {
        const payload = arg.subarray(10);
        if (payload.length > 0) {
          if (this.foodGroup === FoodGroups.NINETEEN && this.type === Types.FIVE) {
            this.date = new Date(Util.Bit.BufferToUInt32(payload.subarray(0, 4)));
            this.count = Util.Bit.BufferToUInt32(
              payload.length > 4 ? payload.subarray(4, 6) : Util.Bit.BytesToBuffer([])
            );
          } else if (this.foodGroup === FoodGroups.ONE && this.type === Types.FIFTEEN) {
            const formattedScreenNameLength = Util.Bit.BufferToUInt8(payload.subarray(0, 1));
            this.formattedScreenName = Util.Bit.BufferToString(payload.subarray(1, formattedScreenNameLength));
            this.warningLevel = Util.Bit.BufferToUInt16(payload.subarray(1 + formattedScreenNameLength, 2));
            this.parameters = Parameter.GetParameters(
              this.foodGroup,
              this.type,
              payload.subarray(1 + formattedScreenNameLength + 2)
            );
          } else if (this.foodGroup === FoodGroups.ONE && this.type === Types.SEVENTEEN) {
            this.idle = Util.Bit.BufferToUInt32(payload.subarray(0, 4));
          } else if (this.foodGroup === FoodGroups.TWO && this.type === Types.FIFTEEN) {
            //payload.splice(0, 4);
            this.interests = Interest.GetInterests(Util.Bit.BufferToBytes(payload.subarray(4)));
          } else if (this.foodGroup === FoodGroups.TWENTYTHREE && this.type === Types.SEVEN) {
            this.authKey = Util.Bit.BufferToString(
              payload.subarray(2, Util.Bit.BufferToUInt16(payload.subarray(0, 2)))
            );
          } else if (this.foodGroup === FoodGroups.ONE && this.type === Types.TWENTYTHREE) {
            this.families = Family.GetFamilies(Util.Bit.BufferToBytes(payload));
          } else if (this.foodGroup === FoodGroups.ONE && this.type === Types.EIGHT) {
            this.groups = Util.Bit.BufferToBytes(payload);
          } else if (this.foodGroup === FoodGroups.TWO && this.type === Types.ELEVEN) {
            this.screenName = Util.Bit.BufferToString(
              payload.subarray(1, Util.Bit.BufferToUInt8(payload.subarray(0, 1)) + 1)
            );
          } else if (this.foodGroup === FoodGroups.ONE && this.type === Types.FOUR) {
            this.groupId = Util.Bit.BufferToUInt16(payload.subarray(0, 2));
            if (payload.length > 0) {
              this.parameters = Parameter.GetParameters(this.foodGroup, this.type, payload.subarray(2));
            }
          } else if (
            this.foodGroup === FoodGroups.NINETEEN &&
            (this.type === Types.EIGHT || this.type === Types.NINE || this.type === Types.TEN)
          ) {
            this.items = SSI.GetSSI(Util.Bit.BufferToBytes(payload));
          } else if (this.foodGroup === FoodGroups.FOUR && this.type === Types.SIX) {
            this.cookie = Util.Bit.BufferToString(payload.subarray(0, 8));
            this.channel = Util.Bit.BufferToUInt16(payload.subarray(8, 2));
            this.screenName = Util.Bit.BufferToString(
              payload.subarray(11, Util.Bit.BufferToUInt8(payload.subarray(10, 1)))
            );
            this.parameters = Parameter.GetParameters(this.foodGroup, this.type, payload);
            this.autoResponse = this.parameters.find((item) => {
              return item.type === ParameterTypes.FOUR;
            });
          } else if (this.foodGroup === FoodGroups.TWO && this.type === Types.TWENTYONE) {
            this.requestFlags = Util.Bit.BufferToBytes(payload.subarray(0, 4));
            this.screenName = Util.Bit.BufferToString(
              payload.subarray(5, Util.Bit.BufferToUInt8(payload.subarray(4, 1)))
            );
          } else if (
            this.foodGroup === FoodGroups.THIRTEEN &&
            (this.type === Types.EIGHT || this.type === Types.FOUR)
          ) {
            this.exchange = Util.Bit.BufferToUInt16(payload.subarray(0, 2));
            this.cookie = Util.Bit.BufferToString(payload.subarray(3, Util.Bit.BufferToUInt8(payload.subarray(2, 1))));
            this.instance = Util.Bit.BufferToUInt16(payload.subarray(3 + this.cookie.length, 2));
            this.detailLevel = Util.Bit.BufferToUInt8(payload.subarray(5 + this.cookie.length, 1));
            this.parameters = Parameter.GetParameters(this.foodGroup, this.type, payload.subarray(2));
          } else if (this.foodGroup === FoodGroups.FOURTEEN && this.type === Types.FIVE) {
            this.cookie = Util.Bit.BufferToString(payload.subarray(0, 8));
            this.channel = Util.Bit.BufferToUInt16(payload.subarray(8, 2));
            this.parameters = Parameter.GetParameters(this.foodGroup, this.type, payload);
          } else {
            this.parameters = Parameter.GetParameters(this.foodGroup, this.type, payload);
          }
        }
      }
      return;
    } else if (typeof arg === 'object' && !Array.isArray(arg)) {
      this.foodGroup = arg.foodGroup;
      this.type = arg.type;
      this.flags = arg.flags;
      this.requestId = arg.requestId;
      if (arg.parameters && Array.isArray(arg.parameters)) {
        this.parameters = arg.parameters;
      }
      if (arg.extensions && typeof arg.extensions === 'object') {
        extend(this, arg.extensions);
      }
      return;
    }
    throw 'Exception: Unable to create new SNAC. Constructor accepts an array of bytes or an object with the parameters foodGroup, type, flags, parameters, and extensions.';
  }

  ToBuffer() {
    let out = [
      ...Util.Bit.UInt16ToBytes(this.foodGroup),
      ...Util.Bit.UInt16ToBytes(this.type),
      ...Util.Bit.UInt16ToBytes(this.flags),
      ...Util.Bit.UInt32ToBytes(this.requestId),
    ];
    // TODO: Make this a big switch statement that calls functions.
    if (this.foodGroup === FoodGroups.TWENTYTHREE && this.type === Types.SEVEN) {
      out = out.concat(Util.Bit.UInt16ToBytes(this.authKey.length), Util.Bit.StringToBytes(this.authKey));
    }
    if (this.foodGroup === FoodGroups.TWO && this.type === Types.SIX) {
      out = out.concat(
        Util.Bit.UInt8ToBytes(this.formattedScreenName.length),
        Util.Bit.StringToBytes(this.formattedScreenName),
        Util.Bit.UInt16ToBytes(0),
        Util.Bit.UInt16ToBytes(3)
      );
    }
    if (this.foodGroup === FoodGroups.THREE && this.type === Types.ELEVEN) {
      out = out.concat(
        Util.Bit.UInt8ToBytes(this.formattedScreenName.length),
        Util.Bit.StringToBytes(this.formattedScreenName),
        Util.Bit.UInt16ToBytes(0),
        Util.Bit.UInt16ToBytes(this.parameters.length)
      );
    }
    if (this.foodGroup === FoodGroups.THREE && this.type === Types.TWELVE) {
      out = out.concat(
        Util.Bit.UInt8ToBytes(this.formattedScreenName.length),
        Util.Bit.StringToBytes(this.formattedScreenName),
        Util.Bit.UInt16ToBytes(0),
        Util.Bit.UInt16ToBytes(this.parameters.length)
      );
    }
    if (this.foodGroup === FoodGroups.FIFTEEN && this.type === Types.FIVE) {
      out = out.concat(
        Util.Bit.UInt16ToBytes(1),
        Util.Bit.UInt16ToBytes(this.interests.length),
        this.interests
          .map(function (item) {
            return item.ToBytes();
          })
          .flat()
      );
    }
    if (this.foodGroup === FoodGroups.ONE && this.type === Types.THREE) {
      out = out.concat(
        this.families
          .map(function (item) {
            return Util.Bit.BufferToBytes(item.ToBuffer());
          })
          .flat()
      );
    }
    if (this.foodGroup === FoodGroups.ONE && this.type === Types.TWENTYFOUR) {
      out = out.concat(
        this.families
          .map(function (item) {
            return Util.Bit.BufferToBytes(item.ToBuffer());
          })
          .flat()
      );
    }
    if (this.foodGroup === FoodGroups.FOUR && this.type === Types.SEVEN) {
      out = out.concat(
        Util.Bit.StringToBytes(this.cookie),
        Util.Bit.UInt16ToBytes(this.channel),
        Util.Bit.UInt8ToBytes(this.formattedScreenName.length),
        Util.Bit.StringToBytes(this.formattedScreenName),
        [
          // FIXME: Figure out what this is.
          0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00,
          0x00, 0x0f, 0x00, 0x04, 0x00, 0x00, 0x57, 0x0b, 0x00, 0x03, 0x00, 0x04, 0x40, 0xe6, 0xda, 0xb8,
        ]
      );
    }
    if (this.foodGroup === FoodGroups.FOUR && this.type === Types.ONE) {
      out = out.concat(Util.Bit.UInt16ToBytes(this.errorId));
    }
    if (this.foodGroup === FoodGroups.SEVEN && this.type === Types.THREE) {
      out = out.concat(Util.Bit.UInt16ToBytes(this.permissions), Util.Bit.UInt16ToBytes(this.parameters.length));
    }
    if (this.foodGroup === FoodGroups.ONE && this.type === Types.FIFTEEN) {
      out = out.concat(
        Util.Bit.UInt8ToBytes(this.formattedScreenName.length),
        Util.Bit.StringToBytes(this.formattedScreenName),
        Util.Bit.UInt16ToBytes(0),
        Util.Bit.UInt16ToBytes(this.parameters.length)
      );
    }
    if (this.foodGroup === FoodGroups.FOURTEEN && this.type === Types.THREE) {
      out = out.concat(
        Util.Bit.UInt8ToBytes(this.formattedScreenName.length),
        Util.Bit.StringToBytes(this.formattedScreenName),
        Util.Bit.UInt16ToBytes(0),
        Util.Bit.UInt16ToBytes(this.parameters.length)
      );
    }
    if (this.foodGroup === FoodGroups.FOURTEEN && this.type === Types.FOUR) {
      out = out.concat(
        Util.Bit.UInt8ToBytes(this.formattedScreenName.length),
        Util.Bit.StringToBytes(this.formattedScreenName),
        Util.Bit.UInt16ToBytes(0),
        Util.Bit.UInt16ToBytes(this.parameters.length)
      );
    }
    if (this.foodGroup === FoodGroups.FOURTEEN && this.type === Types.SIX) {
      out = out.concat(Util.Bit.StringToBytes(this.cookie), Util.Bit.UInt16ToBytes(this.channel));
    }
    if (this.foodGroup === FoodGroups.NINETEEN && this.type === Types.FOURTEEN) {
      // FIXME: Figure out what this is.
      out = out.concat([0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]);
    }
    if (this.parameters && this.parameters.length > 0) {
      out = out.concat(
        this.parameters
          .map(function (item) {
            return Util.Bit.BufferToBytes(item.ToBuffer());
          })
          .flat()
      );
    }
    return Util.Bit.BytesToBuffer(out);
  }
}

export default SNAC;
