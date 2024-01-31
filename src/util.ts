import crypto from 'crypto';

const Bit = {
  ToBuffer: (data?: Buffer | number | number[] | string, position: number = 0, length?: number): Buffer => {
    if (typeof data === 'string') {
      return Buffer.from(data.slice(position, length ?? data.length));
    } else if (data instanceof Buffer) {
      return data.subarray(position, length ?? data.length);
    } else if (typeof data === 'number') {
      if (length === 1 || (data >= 0 && data < 2 << 8)) {
        if (position) {
          throw new Error('Position must be 0 when data is a number.');
        }

        const b = Buffer.alloc(1);
        b.writeUInt8(data);
        return b;
      } else if (length === 2 || (data >= 2 << 8 && data < 2 << 16)) {
        const b = Buffer.alloc(2);
        b.writeUInt16BE(data);
        return b;
      } else if (length === 4 || (data >= 2 << 16 && data < 2 << 32)) {
        const b = Buffer.alloc(4);
        b.writeUint32BE(data);
        return b;
      } else {
        return Buffer.from('');
      }
    } else if (Array.isArray(data)) {
      return Buffer.from(data.slice(position, length));
    } else {
      return Buffer.from('');
    }
  },
  StringToBytes: (str: string) => {
    return Bit.BufferToBytes(Bit.ToBuffer(str));
  },
  ToString: (data: Buffer | number | number[] | string, position: number = 0, length?: number): string => {
    if (typeof data === 'string') {
      return data;
    } else if (data instanceof Buffer) {
      return Bit.ToBuffer(position, length ?? data.length).toString('ascii');
    } else if (typeof data === 'number') {
      return Bit.ToString(Bit.ToBuffer(data, position, length));
    } else if (Array.isArray(data)) {
      return Bit.ToString(Bit.ToBuffer(data, position, length));
    } else {
      return '';
    }
  },
  BufferToBytes: (buffer: Buffer, position: number = 0, length?: number): number[] => {
    return buffer.subarray(position, length ?? buffer.length).toJSON().data;
  },
  BufferToUInt8: (buffer: Buffer, position: number = 0) => {
    return buffer.readUInt8(position);
  },
  BufferToUInt16: (buffer: Buffer, position: number = 0) => {
    return buffer.readUInt16BE(position);
  },
  BufferToUInt32: (buffer: Buffer, position: number = 0) => {
    return buffer.readUInt32BE(position);
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
  BufferToChunkArray: (buffer: Buffer, length: number, formatter: (arg0: Buffer) => number[]) => {
    return Array(Math.ceil(buffer.length / length))
      .map((_, index) => index * length)
      .map((begin) => buffer.subarray(begin, begin + length))
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
        Bit.ToBuffer([
          ...Bit.BufferToBytes(Buffer.from(ticket)),
          ...Bit.BufferToBytes(Crypto.MD5(password)),
          // FIXME: Check whether _AIM_MD5_STRING can be pulled from the packet.
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
