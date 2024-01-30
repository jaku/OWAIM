import crypto from 'crypto';

const Bit = {
  StringToBuffer: (data?: string) => {
    return Buffer.from(data ?? '');
  },
  StringToBytes: (data: string) => {
    return Bit.BufferToBytes(Bit.StringToBuffer(data));
  },
  BufferToString: (data: Buffer) => {
    return data.toString('ascii');
  },
  BufferToBytes: (data: Buffer): number[] => {
    return data.toJSON().data;
  },
  BufferToUInt8: (bytes: Buffer) => {
    return Buffer.from(bytes).readUInt8();
  },
  BufferToUInt16: (bytes: Buffer) => {
    return Buffer.from(bytes).readUInt16BE();
  },
  BufferToUInt32: (bytes: Buffer) => {
    return Buffer.from(bytes).readUInt32BE();
  },
  BytesToBuffer: (data: number[]): Buffer => {
    return Buffer.from(data);
  },
  UInt8ToBytes: (num: number) => {
    const b = Buffer.alloc(1);
    b.writeUInt8(num);
    return b.toJSON().data;
  },
  UInt16ToBytes: (num: number) => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(num);
    return b.toJSON().data;
  },
  UInt32ToBytes: (num: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(num);
    return b.toJSON().data;
  },
  BytesToChunkArray: (bytes: Buffer, size: number, formatter: (arg0: Buffer) => number[]) => {
    return Array(Math.ceil(bytes.length / size))
      .map((_, index) => index * size)
      .map((begin) => bytes.subarray(begin, begin + size))
      .map((array) => {
        return formatter ? formatter(array) : array;
      });
  },

  UserClass: (userClass: number, away: boolean) => {
    return away ? (0x20 & userClass ? userClass : 0x20 | userClass) : 0x20 & userClass ? 0x20 ^ userClass : userClass;
  },
};

const Constants = {
  _FLAP_VERSION: [0, 0, 0, 1] as [number, number, number, number],
  _AIM_MD5_STRING: 'AOL Instant Messenger (SM)',
};

const Crypto = {
  MD5: (string: crypto.BinaryLike) => {
    const hasher = crypto.createHash('md5');
    hasher.update(string);
    return hasher.digest();
  },
};

const Dates = {
  GetTimestamp: () => {
    return Math.floor(new Date().getTime() / 1000);
  },
};

const Strings = {
  DecimalToHexString: (
    code: {
      toString: (arg0: number) => string;
    },
    prefix: boolean = false
  ) => {
    return [prefix ? '0x' : '', ['00', code.toString(16)].join('').slice(-2)].join('');
  },
  DecimalToHex: (num: { toString: (arg0: number) => string }) => {
    return !isNaN(parseInt(num.toString(16)))
      ? parseInt(num.toString(16))
      : ['00', num.toString(16)].join('').slice(-2);
  },
  HexToDecimal: (code: string) => {
    return parseInt(code, 16);
  },
  BytesToHexString: (bytes: number[]) => {
    return bytes
      .map((item: number) => {
        return Strings.DecimalToHexString(item);
      })
      .join('');
  },
  HexStringToBytes: (string: { match: (arg0: RegExp) => string[] }) => {
    return string.match(/.{1,2}/g).map((item: string) => {
      return parseInt(item, 16);
    });
  },
  GenerateInt: (lowerLimit: number, upperLimit: number) => {
    return Math.floor((upperLimit - lowerLimit + 1) * Math.random() + lowerLimit);
  },
  GenerateTicket: () => {
    const out: string[] = [];
    for (let i = 0; i < 10; i++) {
      out.push(String.fromCharCode(Strings.GenerateInt(48, 57)));
    }
    return out.join('');
  },
  GenerateChatCookie: () => {
    const out: string[] = [];
    for (let i = 0; i < 6; i++) {
      out.push(String.fromCharCode(Strings.GenerateInt(48, 57)));
    }
    return out.join('');
  },
  GenerateCookie: () => {
    const out: string[] = [];
    for (let i = 0; i < 256; i++) {
      out.push(String.fromCharCode(Strings.GenerateInt(0, 255)));
    }
    return Crypto.MD5(out.join(''));
  },
  RoastPassword: (ticket: string, password: crypto.BinaryLike) => {
    return Bit.BufferToBytes(
      Crypto.MD5(
        Bit.BytesToBuffer([
          ...Bit.BufferToBytes(Buffer.from(ticket)),
          ...Bit.BufferToBytes(Crypto.MD5(password)),
          ...Bit.BufferToBytes(Buffer.from(Constants._AIM_MD5_STRING)),
        ])
      )
    );
  },
  TrimData: (data: string) => {
    return data.toLowerCase().replace(/\s/g, '');
  },
};

export default {
  Bit,
  Constants,
  Crypto,
  Dates,
  Strings,
};
