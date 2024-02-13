import Family from './family.js';
import Interest from './interest.js';
import Parameter, { ParameterTypes } from './parameter.js';
import SSI from './ssi.js';
import Util from './util.js';

export const enum FoodGroups {
  ZERO = 0x0000,
  OSERVICE = 0x0001,
  LOCATE = 0x0002,
  BUDDY = 0x0003,
  ICBM = 0x0004,
  ADVERT = 0x0005,
  INVITE = 0x0006,
  ADMIN = 0x0007,
  POPUP = 0x0008,
  PD = 0x0009,
  USER_LOOKUP = 0x000a,
  STATS = 0x000b,
  TRANSLATE = 0x000c,
  CHAT_NAV = 0x000d,
  CHAT = 0x000e,
  ODIR = 0x000f,
  BART = 0x0010,
  FEEDBAG = 0x0013,
  ICQ = 0x0015,
  BUCP = 0x0017,
  ALERT = 0x0018,

  // Unused
  PLUGIN = 0x0022,
  UNNAMED_FG_24 = 0x0024,
  MDIR = 0x0025,
  ARS = 0x044a,
}

// FIXME: Types should be different per foodgroup.
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
  THIRTEEN = 0x0d,
  FOURTEEN = 0x0e,
  FIFTEEN = 0x0f,
  SEVENTEEN = 0x11,
  EIGHTEEN = 0x12,
  TWENTYONE = 0x15,
  TWENTYTHREE = 0x17,
  TWENTYFOUR = 0x18,
  THIRTY = 0x1e,
}

interface SNACHeader {
  foodGroup: FoodGroups;
  type: Types;
  flags: number;
  requestId: number;
}

interface SNACPayload {
  count: number;
  date: Date;
  cookie: string;
  authKey: string;
  formattedScreenName: string;
  interests: Interest[];
  families: Family[];
  channel: number;
  errorId: number;
  permissions: number;
  groupId: number;
  screenName: string;
  requestFlags: number[];
  warningLevel: number;
  idle: number;
  groups: number[];
  items: SSI[];
  autoResponse?: Parameter;
  instance: number;
  detailLevel: number;
  exchange: number;
  parameters: Parameter[];
  extensions?: Partial<SNACPayload>;
}

class SNAC {
  header: SNACHeader = {
    foodGroup: FoodGroups.ZERO,
    type: Types.ZERO,
    flags: 0,
    requestId: 0,
  };
  payload: SNACPayload = {
    count: 0,
    date: new Date(),
    cookie: '',
    authKey: '',
    formattedScreenName: '',
    interests: [],
    families: [],
    channel: -1,
    errorId: -1,
    permissions: 0,
    groupId: -1,
    screenName: '',
    requestFlags: [],
    warningLevel: 0,
    idle: 0,
    groups: [],
    items: [],
    autoResponse: undefined,
    instance: -1,
    detailLevel: 0,
    exchange: -1,
    parameters: [],
    extensions: undefined,
  };

  constructor(
    header: Buffer | SNACHeader,
    payload:
      | Buffer
      | SNACPayload
      | {
          parameters: Parameter[];
          extensions?: Partial<SNACPayload>;
        }
  ) {
    if (header instanceof Buffer) {
      this.header = this.headerFromBuffer(header);
    } else {
      this.header = {
        ...this.header,
        ...header,
      };
    }

    if (payload instanceof Buffer) {
      this.payload = this.payloadFromBuffer(payload);
    } else {
      this.payload = {
        ...this.payload,
        ...payload,
      };
    }

    return;
  }

  private headerFromBuffer(header: Buffer): SNACHeader {
    if (header.length < 10) {
      throw new Error('Unable to create SNACHeader.');
    }

    const ret: SNACHeader = this.header;
    let headerPosition = 0;

    ret.foodGroup = Util.Bit.BufferToUInt16(header, headerPosition);
    headerPosition += 2;
    ret.type = Util.Bit.BufferToUInt16(header, headerPosition);
    headerPosition += 2;
    ret.flags = Util.Bit.BufferToUInt16(header, headerPosition);
    headerPosition += 2;
    ret.requestId = Util.Bit.BufferToUInt32(header, headerPosition);
    headerPosition += 2;

    return ret;
  }

  private payloadFromBuffer(payload: Buffer) {
    if (payload.length <= 0) {
      throw new Error('Unable to create new SNACPayload.');
    }

    const ret: SNACPayload = this.payload;
    let payloadPosition = 0;

    switch (this.header.foodGroup) {
      case FoodGroups.BUCP:
        if (this.header.type === Types.SEVEN) {
          const keyLength = Util.Bit.BufferToUInt16(payload, 2);
          payloadPosition += 2;
          ret.authKey = Util.Bit.ToString(payload, payloadPosition, keyLength);
        }
        break;
      case FoodGroups.CHAT_NAV:
        if (this.header.type === Types.FOUR || this.header.type === Types.EIGHT) {
          ret.exchange = Util.Bit.BufferToUInt16(payload, payloadPosition);
          payloadPosition += 2;
          const cookieLength = Util.Bit.BufferToUInt8(payload, payloadPosition);
          payloadPosition += 1;
          ret.cookie = Util.Bit.ToString(payload, payloadPosition, cookieLength);
          payloadPosition += cookieLength;
          ret.instance = Util.Bit.BufferToUInt16(payload, payloadPosition);
          payloadPosition += 2;
          ret.detailLevel = Util.Bit.BufferToUInt8(payload, payloadPosition);
          payloadPosition += 1;
          const parameters = Util.Bit.BufferToBytes(payload, payloadPosition);
          ret.parameters = Parameter.GetParameters(this.header.foodGroup, this.header.type, parameters);
          payloadPosition += parameters.length;
        }
        break;
      case FoodGroups.CHAT:
        if (this.header.type === Types.FIVE) {
          ret.cookie = Util.Bit.ToString(payload, payloadPosition, 8);
          payloadPosition += 8;
          ret.channel = Util.Bit.BufferToUInt16(payload, payloadPosition);
          payloadPosition += 2;
          const parameters = Util.Bit.BufferToBytes(payload, payloadPosition);
          ret.parameters = Parameter.GetParameters(this.header.foodGroup, this.header.type, parameters);
          payloadPosition += parameters.length;
        }
        break;
      case FoodGroups.FEEDBAG:
        if (this.header.type === Types.FIVE) {
          ret.date = new Date(Util.Bit.BufferToUInt32(payload, payloadPosition));
          ret.count = payload.length > 4 ? Util.Bit.BufferToUInt16(payload, payloadPosition) : 0;
        } else if (
          this.header.type === Types.EIGHT ||
          this.header.type === Types.NINE ||
          this.header.type === Types.TEN
        ) {
          ret.items = SSI.GetSSI(Util.Bit.BufferToBytes(payload, payloadPosition));
        }
        break;
      case FoodGroups.ICBM:
        if (this.header.type === Types.SIX) {
          ret.cookie = Util.Bit.ToString(payload, payloadPosition);
          payloadPosition += 8;
          ret.channel = Util.Bit.BufferToUInt16(payload, payloadPosition);
          payloadPosition += 2;
          const screenNameLength = Util.Bit.BufferToUInt8(payload, payloadPosition);
          payloadPosition += 1;
          ret.screenName = Util.Bit.ToString(payload, payloadPosition, screenNameLength);
          payloadPosition += screenNameLength;
          const parameters = Util.Bit.BufferToBytes(payload, payloadPosition);
          ret.parameters = Parameter.GetParameters(this.header.foodGroup, this.header.type, parameters);
          payloadPosition += parameters.length;
          ret.autoResponse = ret.parameters.find((item) => {
            return item.type === ParameterTypes.FOUR;
          });
        }
        break;
      case FoodGroups.LOCATE:
        if (this.header.type === Types.ELEVEN) {
          const screenNameLength = Util.Bit.BufferToUInt8(payload, payloadPosition);
          payloadPosition += 1;
          ret.screenName = Util.Bit.ToString(payload, payloadPosition, screenNameLength);
        } else if (this.header.type === Types.FIFTEEN) {
          //payload.splice(0, 4);
          ret.interests = Interest.GetInterests(Util.Bit.BufferToBytes(payload, payloadPosition));
        } else if (this.header.type === Types.TWENTYONE) {
          ret.requestFlags = Util.Bit.BufferToBytes(payload, payloadPosition, 4);
          payloadPosition += 4;
          const screenNameLength = Util.Bit.BufferToUInt8(payload, payloadPosition);
          payloadPosition += 1;
          ret.screenName = Util.Bit.ToString(payload, payloadPosition, screenNameLength);
          payloadPosition += screenNameLength;
        }
        break;
      case FoodGroups.OSERVICE:
        if (this.header.type === Types.FOUR) {
          ret.groupId = Util.Bit.BufferToUInt16(payload, payloadPosition);
          payloadPosition += 2;
          if (payload.length > payloadPosition) {
            const parameters = Util.Bit.BufferToBytes(payload, payloadPosition);
            ret.parameters = Parameter.GetParameters(this.header.foodGroup, this.header.type, parameters);
            payloadPosition += parameters.length;
          }
        } else if (this.header.type === Types.EIGHT) {
          ret.groups = Util.Bit.BufferToBytes(payload, payloadPosition);
          payloadPosition += ret.groups.length;
        } else if (this.header.type === Types.FIFTEEN) {
          const formattedScreenNameLength = Util.Bit.BufferToUInt8(payload, payloadPosition);
          ret.formattedScreenName = Util.Bit.ToString(payload, payloadPosition, formattedScreenNameLength);
          payloadPosition += formattedScreenNameLength;
          ret.warningLevel = Util.Bit.BufferToUInt16(payload, payloadPosition);
          payloadPosition += 2;
          const parameters = Util.Bit.BufferToBytes(payload, payloadPosition);
          ret.parameters = Parameter.GetParameters(this.header.foodGroup, this.header.type, parameters);
          payloadPosition += parameters.length;
        } else if (this.header.type === Types.SEVENTEEN) {
          ret.idle = Util.Bit.BufferToUInt32(payload, payloadPosition);
        } else if (this.header.type === Types.TWENTYTHREE) {
          ret.families = Family.GetFamilies(Util.Bit.BufferToBytes(payload, payloadPosition));
        }
        break;
      default: {
        const parameters = Util.Bit.BufferToBytes(payload, payloadPosition);
        ret.parameters = Parameter.GetParameters(this.header.foodGroup, this.header.type, parameters);
        payloadPosition += parameters.length;

        break;
      }
    }

    return ret;
  }

  private headerToBuffer() {
    return [
      ...Util.Bit.UInt16ToBytes(this.header.foodGroup),
      ...Util.Bit.UInt16ToBytes(this.header.type),
      ...Util.Bit.UInt16ToBytes(this.header.flags),
      ...Util.Bit.UInt32ToBytes(this.header.requestId),
    ];
  }

  private payloadToBuffer() {
    let out: number[] = [];
    // TODO: Make this a big switch statement that calls functions.
    switch (this.header.foodGroup) {
      case FoodGroups.ADMIN:
        if (this.header.type === Types.THREE) {
          out = [
            ...Util.Bit.UInt16ToBytes(this.payload.permissions),
            ...Util.Bit.UInt16ToBytes(this.payload.parameters?.length ?? 0),
          ];
        }
        break;
      case FoodGroups.BUCP:
        if (this.header.type === Types.SEVEN) {
          out = [
            ...Util.Bit.UInt16ToBytes(this.payload.authKey.length),
            ...Util.Bit.StringToBytes(this.payload.authKey),
          ];
        }
        break;
      case FoodGroups.BUDDY:
        if (this.header.type === Types.ELEVEN) {
          out = [
            ...Util.Bit.UInt8ToBytes(this.payload.formattedScreenName.length),
            ...Util.Bit.StringToBytes(this.payload.formattedScreenName),
            ...Util.Bit.UInt16ToBytes(0),
            ...Util.Bit.UInt16ToBytes(this.payload.parameters?.length ?? 0),
          ];
        } else if (this.header.type === Types.TWELVE) {
          out = [
            ...Util.Bit.UInt8ToBytes(this.payload.formattedScreenName.length),
            ...Util.Bit.StringToBytes(this.payload.formattedScreenName),
            ...Util.Bit.UInt16ToBytes(0),
            ...Util.Bit.UInt16ToBytes(this.payload.parameters?.length ?? 0),
          ];
        }
        break;
      case FoodGroups.CHAT:
        if (this.header.type === Types.THREE) {
          out = [
            ...Util.Bit.UInt8ToBytes(this.payload.formattedScreenName.length),
            ...Util.Bit.StringToBytes(this.payload.formattedScreenName),
            ...Util.Bit.UInt16ToBytes(0),
            ...Util.Bit.UInt16ToBytes(this.payload.parameters?.length ?? 0),
          ];
        } else if (this.header.type === Types.FOUR) {
          out = [
            ...Util.Bit.UInt8ToBytes(this.payload.formattedScreenName.length),
            ...Util.Bit.StringToBytes(this.payload.formattedScreenName),
            ...Util.Bit.UInt16ToBytes(0),
            ...Util.Bit.UInt16ToBytes(this.payload.parameters?.length ?? 0),
          ];
        } else if (this.header.type === Types.SIX) {
          out = [...Util.Bit.StringToBytes(this.payload.cookie), ...Util.Bit.UInt16ToBytes(this.payload.channel)];
        }
        break;
      case FoodGroups.FEEDBAG:
        if (this.header.type === Types.FOURTEEN) {
          // FIXME: Figure out what this is.
          out = [0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
        }
        break;
      case FoodGroups.ICBM:
        if (this.header.type === Types.SEVEN) {
          out = [
            ...Util.Bit.StringToBytes(this.payload.cookie),
            ...Util.Bit.UInt16ToBytes(this.payload.channel),
            ...Util.Bit.UInt8ToBytes(this.payload.formattedScreenName.length),
            ...Util.Bit.StringToBytes(this.payload.formattedScreenName),
            ...[
              // FIXME: Figure out what this is.
              0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x01,
              0x00, 0x00, 0x0f, 0x00, 0x04, 0x00, 0x00, 0x57, 0x0b, 0x00, 0x03, 0x00, 0x04, 0x40, 0xe6, 0xda, 0xb8,
            ],
          ];
        } else if (this.header.type === Types.ONE) {
          out = [...Util.Bit.UInt16ToBytes(this.payload.errorId)];
        }
        break;
      case FoodGroups.LOCATE:
        if (this.header.type === Types.SIX) {
          out = [
            ...Util.Bit.UInt8ToBytes(this.payload.formattedScreenName.length),
            ...Util.Bit.StringToBytes(this.payload.formattedScreenName),
            ...Util.Bit.UInt16ToBytes(0),
            ...Util.Bit.UInt16ToBytes(3),
          ];
        }
        break;
      case FoodGroups.ODIR:
        if (this.header.type === Types.FIVE) {
          out = [
            ...Util.Bit.UInt16ToBytes(1),
            ...Util.Bit.UInt16ToBytes(this.payload.interests.length),
            ...this.payload.interests
              .map(function (item) {
                return item.ToBytes();
              })
              .flat(),
          ];
        }
        break;
      case FoodGroups.OSERVICE:
        if (this.header.type === Types.THREE) {
          out = [
            ...this.payload.families
              .map(function (item) {
                return Util.Bit.UInt16ToBytes(item.type);
              })
              .flat(),
          ];
        } else if (this.header.type === Types.TWENTYFOUR) {
          out = [
            ...this.payload.families
              .map(function (item) {
                return Util.Bit.UInt16ToBytes(item.type);
              })
              .flat(),
          ];
        } else if (this.header.type === Types.FIFTEEN) {
          out = [
            ...Util.Bit.UInt8ToBytes(this.payload.formattedScreenName.length),
            ...Util.Bit.StringToBytes(this.payload.formattedScreenName),
            ...Util.Bit.UInt16ToBytes(0),
            ...Util.Bit.UInt16ToBytes(this.payload.parameters?.length ?? 0),
          ];
        }
        break;
      default:
        break;
    }

    if (this.payload.parameters && this.payload.parameters?.length > 0) {
      out = out.concat(
        this.payload.parameters
          .map(function (item) {
            return Util.Bit.BufferToBytes(item.ToBuffer());
          })
          .flat()
      );
    }

    return out;
  }

  ToBuffer() {
    const out: number[] = [...this.headerToBuffer(), ...this.payloadToBuffer()];

    return Util.Bit.ToBuffer(out);
  }
}

export default SNAC;
