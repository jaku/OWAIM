import ChatManager from './chatmanager.js';
import Family from './family.js';
import FLAP from './flap.js';
import Net from 'net';
import Options from './options.js';
import Parameter, { ParameterTypes } from './parameter.js';
import SessionManager, { Session, SessionServices as SessionService } from './sessionmanager.js';
import SNAC, { FoodGroups as FoodGroups, Types as SNACTypes, Types } from './snac.js';
import SSI from './ssi.js';
import User from './user.js';
import Util from './util.js';
import Fragment from './fragment.js';
import tmi from 'tmi.js';

import express from 'express';

const app = express();
const port = 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const opts = {
  identity: {
    username: 'justinfan12345', // Use a justinfan username for read-only mode
  },
  channels: [
    'jaku', // Replace this with the name of the channel you want to join
  ],
};

let ready = false;
// Create a client with the configuration
const client = new tmi.client(opts);

// Register event handlers
client.on('message', onMessageHandler);
client.on('connected', onConnectedHandler);

// Connect to Twitch
void client.connect();

// Called every time a message comes in
function onMessageHandler(target: string, context: tmi.ChatUserstate, msg: string, self: boolean) {
  if (self) {
    return;
  } // Ignore messages from the bot itself

  // Remove whitespace from chat message
  const commandName = msg.trim();
  if (ready) sentAIMMessage(context['display-name'], commandName);
  // Log the username and message to the console
  console.log(`${context['display-name']}: ${commandName}`);
}

// Called every time the bot connects to Twitch chat
function onConnectedHandler(addr, port) {
  console.log(`* Connected to ${addr}:${port}`);
}

let _existingSession;
let _snac;
let _session;
let _options: Options;

try {
  const json = JSON.parse(process.argv.slice(2).join('').replace(/'/g, '"')) as Options;
  _options = new Options(json);
} catch (err) {
  throw new Error('Could not parse options argument.');
}

const _sessions = new SessionManager();

const _chatrooms = new ChatManager();

function SendData(session: Session, requestId: number, channel: number, bytes: number[], echo: boolean = false) {
  session.sequence++;
  if (session.sequence > 65535) {
    session.sequence = 0;
  }

  if (channel === 2 && requestId > 0) {
    bytes.splice(6, 4, ...Util.Bit.UInt32ToBytes(requestId));
  }
  const packet = new FLAP(Util.Bit.BytesToBuffer([channel, session.sequence, ...bytes]));
  if (echo) {
    console.log('packet', JSON.stringify(Util.Bit.BytesToBuffer(packet.ToBytes())));
  }
  session.socket.write(Util.Bit.BytesToBuffer(packet.ToBytes()));
}
const authServer = Net.createServer((socket) => {
  const session = _sessions.add({
    socket: socket,
    sequence: 0,
    groupId: -1,
    buffer: Util.Bit.BytesToBuffer([]),
    parent: undefined,
    chat: undefined,
    user: undefined,
    cookie: '',
    services: [],
    ticket: '',
  });

  session.socket.on('error', (err) => {
    console.log('<!> Auth server socket error:', err);
  });

  session.socket.on('end', () => {
    session.socket.destroy();
    session.sequence = 0;
    if (!session.user) {
      _sessions.remove(session);
    }
  });

  session.socket.on('data', (data) => {
    session.buffer = { ...session.buffer, ...data };

    let endProcStream = false;
    if (session.buffer.length < 10) {
      return;
    }
    while (session.buffer.length > 0 && !endProcStream) {
      if (session.buffer.subarray(0, 1)[0] !== 0x2a) {
        //console.log('<!> non FLAP packet recieved on BOS socket!');
        return;
      }
      const size = Util.Bit.BufferToUInt16(session.buffer.subarray(4, 6));
      if (session.buffer.length >= 6 + size) {
        void ProcessRequest(
          session,
          session.buffer.subarray(0, 6),
          session.buffer.subarray(6, 6 + size),
          session.buffer.subarray(0, 6 + size)
        );
      } else {
        endProcStream = true;
      }
    }
    return;
  });

  SendData(session, 0, 1, Util.Constants._FLAP_VERSION);

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async function ProcessRequest(session: Session, header: Buffer, data: Buffer, _bytes: Buffer) {
    // get FLAP header.
    const flap = new FLAP(header);

    // expect: 2, channel: SNAC
    if (flap.channel === 2) {
      // get SNAC packet.
      const snac = new SNAC(data);

      // expect: 0x00 0x17 0x00 0x06
      // method: auth key request
      if (snac.foodGroup === FoodGroups.TWENTYTHREE && snac.type === SNACTypes.SIX) {
        const screenName = snac.parameters.find((item: { type: ParameterTypes }) => {
          return item.type === ParameterTypes.ONE;
        });
        if (screenName) {
          const user = await User.getSingleUser(Util.Bit.BufferToString(screenName.data as Buffer));
          if (!user) {
            // user not found.
            SendData(
              session,
              0,
              2,
              Util.Bit.BufferToBytes(
                new SNAC({
                  foodGroup: FoodGroups.TWENTYTHREE,
                  type: SNACTypes.THREE,
                  flags: 0,
                  requestId: 0,
                  parameters: [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: screenName.data,
                    }),
                    new Parameter({
                      type: ParameterTypes.FOUR,
                      data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/unregistered'),
                    }),
                    new Parameter({
                      type: ParameterTypes.EIGHT,
                      data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(4)),
                    }),
                  ],
                }).ToBuffer()
              )
            );
            return;
          }
          // if (user.ScreenName !== Util.Bit.BytesToString(screenName.data)) {
          //     // user not the same.
          ////     console.log("HMM")
          //     SendData(session, 0, 2, new SNAC({
          //         foodGroup: SNACFoodGroups.TWENTYTHREE,
          //         type: SNACTypes.THREE,
          //         flags: 0,
          //         requestId: 0,
          //         parameters: [
          //             new Parameter({ type: ParameterTypes.ONE, data: screenName.data }),
          //             new Parameter({ type: ParameterTypes.FOUR, data: Util.Bit.BufferBytes('https://www.lwrca.se/owaim/unregistered') }),
          //             new Parameter({ type: ParameterTypes.EIGHT, data: Util.Bit.UInt16ToBytes(7) })
          //         ]
          //     }).ToBytes());
          //     return;
          // }
          if (user.Deleted) {
            // user deleted.
            SendData(
              session,
              0,
              2,
              Util.Bit.BufferToBytes(
                new SNAC({
                  foodGroup: FoodGroups.TWENTYTHREE,
                  type: Types.THREE,
                  flags: 0,
                  requestId: 0,
                  parameters: [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: screenName.data,
                    }),
                    new Parameter({
                      type: ParameterTypes.FOUR,
                      data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/deleted'),
                    }),
                    new Parameter({
                      type: ParameterTypes.EIGHT,
                      data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(8)),
                    }),
                  ],
                }).ToBuffer()
              )
            );
            return;
          }
          if (user.Suspended) {
            // user suspended.
            SendData(
              session,
              0,
              2,
              Util.Bit.BufferToBytes(
                new SNAC({
                  foodGroup: FoodGroups.TWENTYTHREE,
                  type: Types.THREE,
                  flags: 0,
                  requestId: 0,
                  parameters: [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: screenName.data,
                    }),
                    new Parameter({
                      type: ParameterTypes.FOUR,
                      data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/suspended'),
                    }),
                    new Parameter({
                      type: ParameterTypes.EIGHT,
                      data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(17)),
                    }),
                  ],
                }).ToBuffer()
              )
            );
            return;
          }
          session.ticket = Util.Strings.GenerateTicket();
          SendData(
            session,
            0,
            2,
            Util.Bit.BufferToBytes(
              new SNAC({
                foodGroup: FoodGroups.TWENTYTHREE,
                type: Types.SEVEN,
                flags: 0,
                requestId: 0,
                extensions: {
                  authKey: session.ticket,
                },
              }).ToBuffer()
            )
          );
          return;
        }
        // user not sent.
        SendData(
          session,
          0,
          2,
          Util.Bit.BufferToBytes(
            new SNAC({
              foodGroup: FoodGroups.TWENTYTHREE,
              type: Types.THREE,
              flags: 0,
              requestId: 0,
              parameters: [
                new Parameter({
                  type: ParameterTypes.ONE,
                  data: Util.Bit.StringToBuffer(screenName ?? ''),
                }),
                new Parameter({
                  type: ParameterTypes.FOUR,
                  data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/unregistered'),
                }),
                new Parameter({
                  type: ParameterTypes.EIGHT,
                  data: Util.Bit.BytesToBuffer(Util.Bit.UInt8ToBytes(7)),
                }),
              ],
            }).ToBuffer()
          )
        );
        return;
      }

      // expect: 0x00 0x17 0x00 0x02
      // method: auth
      if (snac.foodGroup === FoodGroups.TWENTYTHREE && snac.type === Types.TWO) {
        const screenName = snac.parameters.find((item) => {
          return item.type === ParameterTypes.ONE;
        });
        const roastedPassword = snac.parameters.find((item) => {
          return item.type === ParameterTypes.THIRTYSEVEN;
        });
        if (screenName && roastedPassword) {
          const user = await User.getSingleUser(Util.Bit.BufferToString(screenName.data as Buffer));
          if (!user) {
            // user not found.
            SendData(
              session,
              0,
              2,
              Util.Bit.BufferToBytes(
                new SNAC({
                  foodGroup: FoodGroups.TWENTYTHREE,
                  type: Types.THREE,
                  flags: 0,
                  requestId: 0,
                  parameters: [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: screenName.data,
                    }),
                    new Parameter({
                      type: ParameterTypes.FOUR,
                      data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/unregistered'),
                    }),
                    new Parameter({
                      type: ParameterTypes.EIGHT,
                      data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(4)),
                    }),
                  ],
                }).ToBuffer()
              )
            );
            return;
          }
          // if (user.ScreenName !== Util.Bit.BytesToString(screenName.data)) {
          //     // user not the same.
          ////     console.log("BNOE#")
          //     SendData(session, 0, 2, new SNAC({
          //        foodGroup: FoodGroups.TWENTYTHREE,
          //        type: Types.THREE,
          //         flags: 0,
          //         requestId: 0,
          //         parameters: [
          //             new Parameter({ type: 0x01, data: screenName.data }),
          //             new Parameter({ type: 0x04, data: Util.Bit.BufferBytes('https://www.lwrca.se/owaim/unregistered') }),
          //             new Parameter({ type: 0x08, data: Util.Bit.UInt16ToBytes(7) })
          //         ]
          //     }).ToBytes());
          //     return;
          // }
          if (user.Deleted) {
            // user deleted.
            SendData(
              session,
              0,
              2,
              Util.Bit.BufferToBytes(
                new SNAC({
                  foodGroup: FoodGroups.TWENTYTHREE,
                  type: Types.THREE,
                  flags: 0,
                  requestId: 0,
                  parameters: [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: screenName.data,
                    }),
                    new Parameter({
                      type: ParameterTypes.FOUR,
                      data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/deleted'),
                    }),
                    new Parameter({
                      type: ParameterTypes.EIGHT,
                      data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(8)),
                    }),
                  ],
                }).ToBuffer()
              )
            );
            return;
          }
          if (user.Suspended) {
            // user suspended.
            SendData(
              session,
              0,
              2,
              Util.Bit.BufferToBytes(
                new SNAC({
                  foodGroup: FoodGroups.TWENTYTHREE,
                  type: Types.THREE,
                  flags: 0,
                  requestId: 0,
                  parameters: [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: screenName.data,
                    }),
                    new Parameter({
                      type: ParameterTypes.FOUR,
                      data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/suspended'),
                    }),
                    new Parameter({
                      type: ParameterTypes.EIGHT,
                      data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(17)),
                    }),
                  ],
                }).ToBuffer()
              )
            );
            return;
          }
          const roastedPasswordHash = Util.Strings.BytesToHexString(
            Util.Bit.BufferToBytes(roastedPassword.data as Buffer)
          );
          const userPasswordHash = Util.Strings.BytesToHexString(
            Util.Strings.RoastPassword(session.ticket, user.Password)
          );
          if (roastedPasswordHash === userPasswordHash) {
            session.cookie = Util.Strings.BytesToHexString(Util.Bit.BufferToBytes(Util.Strings.GenerateCookie()));
            session.user = user;
            // user good.
            SendData(
              session,
              0,
              2,
              Util.Bit.BufferToBytes(
                new SNAC({
                  foodGroup: FoodGroups.TWENTYTHREE,
                  type: Types.THREE,
                  flags: 0,
                  requestId: 0,
                  parameters: [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: Util.Bit.StringToBuffer(user.ScreenName),
                    }),
                    new Parameter({
                      type: ParameterTypes.FIVE,
                      data: Util.Bit.StringToBuffer([_options.ip, _options.bosPort].join(':')),
                    }),
                    new Parameter({
                      type: ParameterTypes.SIX,
                      data: Util.Bit.StringToBuffer(session.cookie),
                    }),
                    new Parameter({
                      type: ParameterTypes.SEVENTEEN,
                      data: Util.Bit.StringToBuffer(session.user.EmailAddress),
                    }),
                    new Parameter({
                      type: ParameterTypes.EIGHTYFOUR,
                      data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/change-password'),
                    }),
                  ],
                }).ToBuffer()
              )
            );
            return;
          }
          // invalid password.
          SendData(
            session,
            0,
            2,
            Util.Bit.BufferToBytes(
              new SNAC({
                foodGroup: FoodGroups.TWENTYTHREE,
                type: Types.THREE,
                flags: 0,
                requestId: 0,
                parameters: [
                  new Parameter({
                    type: ParameterTypes.ONE,
                    data: screenName.data,
                  }),
                  new Parameter({
                    type: ParameterTypes.FOUR,
                    data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/password'),
                  }),
                  new Parameter({
                    type: ParameterTypes.EIGHT,
                    data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(5)),
                  }),
                ],
              }).ToBuffer()
            )
          );
          return;
        }
        // user not sent.
        SendData(
          session,
          0,
          2,
          Util.Bit.BufferToBytes(
            new SNAC({
              foodGroup: FoodGroups.TWENTYTHREE,
              type: Types.THREE,
              flags: 0,
              requestId: 0,
              parameters: [
                new Parameter({
                  type: ParameterTypes.ONE,
                  data: screenName?.data ?? Util.Bit.StringToBuffer(''),
                }),
                new Parameter({
                  type: ParameterTypes.FOUR,
                  data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/unregistered'),
                }),
                new Parameter({
                  type: ParameterTypes.EIGHT,
                  data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(7)),
                }),
              ],
            }).ToBuffer()
          )
        );
        return;
      }

      // All other SNACs
      //console.log('Auth unhandled', snac);
    }

    // expect: 4, channel: disconnect
    if (flap.channel === 4) {
      return;
    }
  }
});
authServer
  .listen(_options.authPort, _options.ip)
  .on('listening', () => {
    console.log('Auth socket listening on', authServer.address());
  })
  .on('error', (err) => {
    console.log('Auth server socket error:', err);
  });

function overwriteSnacData(snac: SNAC, hexString: string) {
  // Ensure hexString is defined and a string
  if (hexString.length === 0) {
    console.error('Invalid or empty hexString provided.');
    return snac; // Return the original snac object unchanged
  }

  // Convert the hex string to a byte array, ensuring hexString is a valid hex
  const hexBuffer = hexString.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [];

  // Iterate through the 'parameters' array in the 'snac' object
  snac.parameters.forEach((parameter) => {
    // Only overwrite 'data' for parameters with 'length' of 1 or more
    if (parameter.length > 0) {
      parameter.data = Util.Bit.BytesToBuffer(hexBuffer);
    }
  });

  return snac;
}

const bosServer = Net.createServer((socket) => {
  const session = _sessions.add({
    sequence: 0,
    socket: socket,
    buffer: Util.Bit.BytesToBuffer([]),
    groupId: -1,
    cookie: '',
    services: [],
    ticket: '',
  });
  session.socket.on('error', (err) => {
    console.log('<!> BOS server socket error:', err);
  });
  session.socket.on('end', () => {
    session.socket.destroy();
    session.sequence = 0;
    if (session.user) {
      session.user.SignedOn = false;
      void session.user.updateStatus(session, _sessions, SendData);
    }
    _sessions.remove(session);
  });
  session.socket.on('data', (data) => {
    session.buffer = { ...session.buffer, ...data };
    let endProcStream = false;
    if (session.buffer.length < 10) {
      return;
    }
    while (session.buffer.length > 0 && !endProcStream) {
      if (session.buffer.subarray(0, 1)[0] !== 0x2a) {
        //console.log('<!> non FLAP packet recieved on BOS socket!');
        return;
      }
      const size = Util.Bit.BufferToUInt16(session.buffer.slice(4, 6));
      if (session.buffer.length >= 6 + size) {
        void ProcessRequest(
          session,
          session.buffer.subarray(0, 6),
          session.buffer.slice(6, 6 + size),
          session.buffer.slice(0, 6 + size)
        );
      } else {
        endProcStream = true;
      }
    }
  });
  SendData(session, 0, 1, Util.Constants._FLAP_VERSION);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async function ProcessRequest(session: Session, header: Buffer, data: Buffer, _bytes: Buffer) {
    // get FLAP header.
    const flap = new FLAP(header);
    switch (flap.channel) {
      case 1: {
        // auth
        if (data.length > 4) {
          const parameters = Parameter.GetParameters(FoodGroups.ZERO, Types.ZERO, data.subarray(4));
          const cookie = parameters.find((item) => {
            return item.type === ParameterTypes.SIX;
          });
          if (cookie) {
            const existingSession = {
              ...session,
              ..._sessions.item({
                cookie: cookie.data.toString(),
              }),
            };
            if (existingSession) {
              SendData(
                session,
                0,
                2,
                Util.Bit.BufferToBytes(
                  new SNAC({
                    foodGroup: FoodGroups.ONE,
                    type: Types.THREE,
                    flags: 0,
                    requestId: 0,
                    extensions: {
                      families: [1, 2, 3, 4, 6, 7, 8, 9, 16, 10, 24, 11, 19, 21, 34, 37, 15],
                    },
                  }).ToBuffer()
                )
              );
              return;
            }
            SendData(session, 0, 4, []);
            return;
          }
          SendData(session, 0, 4, []);
          return;
        }
        SendData(session, 0, 4, []);
        return;
      }
      case 2: {
        // SNAC
        // get SNAC packet
        const snac = new SNAC(data);
        switch (snac.foodGroup) {
          case FoodGroups.ONE: {
            // generic service controls
            switch (snac.type) {
              case Types.TWO: {
                // service client ready.
                if (session.user) {
                  //console.log('<+>', session.user.ScreenName, 'has signed on successfully.');
                  session.user.SignedOn = true;
                  session.user.SignedOnTimestamp = new Date(Util.Dates.GetTimestamp());
                  await session.user.updateStatus(session, _sessions, SendData);
                }
                return;
              }
              case Types.FOUR: {
                // new service request.
                if (!session.services) {
                  session.services = [];
                }
                const extCookie = snac.parameters
                  ? snac.parameters.find((item) => {
                      return item.type === ParameterTypes.ONE;
                    })
                  : undefined;
                const serviceSession: SessionService = { groupId: snac.groupId, cookie: '' };
                if (extCookie) {
                  const dataExtCookie = extCookie.data as Buffer;
                  // eslint-disable-next-line @typescript-eslint/no-unused-vars
                  const extCookieType = dataExtCookie.subarray(0, 2);
                  const extCookieLen = dataExtCookie.subarray(2, 3);
                  const extCookieData = dataExtCookie.subarray(3, 3 + Util.Bit.BufferToUInt8(extCookieLen));
                  serviceSession.cookie = [Util.Bit.BufferToString(extCookieData), session.user?.ScreenName].join('.');
                } else {
                  serviceSession.cookie = session.user?.ScreenName ?? '';
                }
                //session.services.push(serviceSession);
                // SendData(session, snac.requestId, 2, new SNAC({
                //     foodGroup: FoodGroups.ONE,
                //     type: Types.FIVE,
                //     flags: 0,
                //     requestId: snac.requestId,
                //     parameters: [
                //         new Parameter({ type: 0x0d, data: snac.groupId }),
                //         new Parameter({ type: 0x05, data: Util.Bit.BufferBytes([_options.ip, _options.aosPort].join(':')) }),
                //         new Parameter({ type: 0x06, data: Util.Bit.BufferBytes(serviceSession.cookie) })
                //     ]
                // }).ToBytes());

                return;
              }
              case Types.SIX: {
                // rate limits request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.ONE,
                      type: Types.SEVEN,
                      flags: 0,
                      requestId: 0,
                    }).ToBuffer()
                  ).concat([
                    // FIXME: Figure out what this is.
                    0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x09, 0xc4, 0x00, 0x00, 0x07, 0xd0,
                    0x00, 0x00, 0x05, 0xdc, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00, 0x16, 0xdc, 0x00, 0x00, 0x17, 0x70,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x0b, 0xb8, 0x00,
                    0x00, 0x07, 0xd0, 0x00, 0x00, 0x05, 0xdc, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x17, 0x70, 0x00,
                    0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00,
                    0x0e, 0x74, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x00, 0x05, 0xdc, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00,
                    0x17, 0x70, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                    0x14, 0x00, 0x00, 0x15, 0x7c, 0x00, 0x00, 0x14, 0xb4, 0x00, 0x00, 0x10, 0x68, 0x00, 0x00, 0x0b,
                    0xb8, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x1f, 0x40, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x05,
                    0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x15, 0x7c, 0x00, 0x00, 0x14, 0xb4, 0x00, 0x00, 0x10, 0x68,
                    0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x1f, 0x40, 0x00, 0x00, 0x00, 0x7b,
                    0x00, 0x00, 0x01, 0x00, 0x91, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
                    0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00,
                    0x07, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x00,
                    0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00,
                    0x0f, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x11, 0x00, 0x01, 0x00, 0x12, 0x00, 0x01, 0x00,
                    0x13, 0x00, 0x01, 0x00, 0x14, 0x00, 0x01, 0x00, 0x15, 0x00, 0x01, 0x00, 0x16, 0x00, 0x01, 0x00,
                    0x17, 0x00, 0x01, 0x00, 0x18, 0x00, 0x01, 0x00, 0x19, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x01, 0x00,
                    0x1b, 0x00, 0x01, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x01, 0x00,
                    0x1f, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x21, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00,
                    0x02, 0x00, 0x02, 0x00, 0x03, 0x00, 0x02, 0x00, 0x04, 0x00, 0x02, 0x00, 0x06, 0x00, 0x02, 0x00,
                    0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x02, 0x00,
                    0x0d, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00,
                    0x11, 0x00, 0x02, 0x00, 0x12, 0x00, 0x02, 0x00, 0x13, 0x00, 0x02, 0x00, 0x14, 0x00, 0x02, 0x00,
                    0x15, 0x00, 0x03, 0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00,
                    0x06, 0x00, 0x03, 0x00, 0x07, 0x00, 0x03, 0x00, 0x08, 0x00, 0x03, 0x00, 0x09, 0x00, 0x03, 0x00,
                    0x0a, 0x00, 0x03, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00,
                    0x02, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x04, 0x00,
                    0x07, 0x00, 0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x09, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x04, 0x00,
                    0x0b, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04, 0x00,
                    0x0f, 0x00, 0x04, 0x00, 0x10, 0x00, 0x04, 0x00, 0x11, 0x00, 0x04, 0x00, 0x12, 0x00, 0x04, 0x00,
                    0x13, 0x00, 0x04, 0x00, 0x14, 0x00, 0x06, 0x00, 0x01, 0x00, 0x06, 0x00, 0x02, 0x00, 0x06, 0x00,
                    0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x09, 0x00, 0x01, 0x00, 0x09, 0x00,
                    0x02, 0x00, 0x09, 0x00, 0x03, 0x00, 0x09, 0x00, 0x04, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
                    0x0a, 0x00, 0x09, 0x00, 0x0b, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x0a, 0x00,
                    0x03, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x0b, 0x00,
                    0x04, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x03, 0x00, 0x13, 0x00,
                    0x01, 0x00, 0x13, 0x00, 0x02, 0x00, 0x13, 0x00, 0x03, 0x00, 0x13, 0x00, 0x04, 0x00, 0x13, 0x00,
                    0x05, 0x00, 0x13, 0x00, 0x06, 0x00, 0x13, 0x00, 0x07, 0x00, 0x13, 0x00, 0x08, 0x00, 0x13, 0x00,
                    0x09, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x13, 0x00, 0x0b, 0x00, 0x13, 0x00, 0x0c, 0x00, 0x13, 0x00,
                    0x0d, 0x00, 0x13, 0x00, 0x0e, 0x00, 0x13, 0x00, 0x0f, 0x00, 0x13, 0x00, 0x10, 0x00, 0x13, 0x00,
                    0x11, 0x00, 0x13, 0x00, 0x12, 0x00, 0x13, 0x00, 0x13, 0x00, 0x13, 0x00, 0x14, 0x00, 0x13, 0x00,
                    0x15, 0x00, 0x13, 0x00, 0x16, 0x00, 0x13, 0x00, 0x17, 0x00, 0x13, 0x00, 0x18, 0x00, 0x13, 0x00,
                    0x19, 0x00, 0x13, 0x00, 0x1a, 0x00, 0x13, 0x00, 0x1b, 0x00, 0x13, 0x00, 0x1c, 0x00, 0x13, 0x00,
                    0x1d, 0x00, 0x13, 0x00, 0x1e, 0x00, 0x13, 0x00, 0x1f, 0x00, 0x13, 0x00, 0x20, 0x00, 0x13, 0x00,
                    0x21, 0x00, 0x13, 0x00, 0x22, 0x00, 0x13, 0x00, 0x23, 0x00, 0x13, 0x00, 0x24, 0x00, 0x13, 0x00,
                    0x25, 0x00, 0x13, 0x00, 0x26, 0x00, 0x13, 0x00, 0x27, 0x00, 0x13, 0x00, 0x28, 0x00, 0x15, 0x00,
                    0x01, 0x00, 0x15, 0x00, 0x02, 0x00, 0x15, 0x00, 0x03, 0x00, 0x02, 0x00, 0x06, 0x00, 0x03, 0x00,
                    0x04, 0x00, 0x03, 0x00, 0x05, 0x00, 0x09, 0x00, 0x05, 0x00, 0x09, 0x00, 0x06, 0x00, 0x09, 0x00,
                    0x07, 0x00, 0x09, 0x00, 0x08, 0x00, 0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00,
                    0x06, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0x09, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x05, 0x00,
                    0x00,
                  ])
                );
                return;
              }
              case Types.EIGHT: {
                // rate limits acceptance notification.
                return;
              }
              case Types.FOURTEEN: {
                // self information request.
                SendData(
                  session,
                  0,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.ONE,
                      type: Types.FIFTEEN,
                      flags: 0,
                      requestId: 0,
                      parameters: [
                        new Parameter({
                          type: ParameterTypes.ONE,
                          data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                        }),
                        new Parameter({
                          type: ParameterTypes.SIX,
                          data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                        }),
                        new Parameter({
                          type: ParameterTypes.FIFTEEN,
                          data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                        }),
                        new Parameter({
                          type: ParameterTypes.THREE,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt32ToBytes(Util.Dates.GetTimestamp())),
                        }),
                        new Parameter({
                          type: ParameterTypes.TEN,
                          data: Util.Bit.BytesToBuffer(
                            // FIXME: Add a proper regex IP parser.
                            session.socket?.remoteAddress
                              ?.split('.')
                              .map((item) => {
                                return Util.Bit.UInt8ToBytes(parseInt(item));
                              })
                              .flat() ?? [0, 0, 0, 0]
                          ),
                        }),
                        new Parameter({
                          type: ParameterTypes.THIRTY,
                          data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                        }),
                        new Parameter({
                          type: ParameterTypes.FIVE,
                          data: Util.Bit.BytesToBuffer(
                            Util.Bit.UInt32ToBytes((session.user?.CreationDate ?? new Date(0)).getTime())
                          ),
                        }),
                        new Parameter({
                          type: ParameterTypes.TWELVE,
                          data: Util.Bit.BytesToBuffer([
                            0xae, 0x44, 0xbe, 0xa5, 0x00, 0x00, 0x16, 0x44, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          ]),
                        }),
                      ],
                      extensions: {
                        formattedScreenName: session.user?.FormattedScreenName,
                      },
                    }).ToBuffer()
                  )
                );
                return;
              }
              case Types.TWENTYTHREE: {
                // service host version request.
                SendData(
                  session,
                  0,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.ONE,
                      type: Types.TWENTYFOUR,
                      flags: 0,
                      requestId: 0,
                      extensions: {
                        families: [
                          new Family({ type: 1, version: 3 }),
                          new Family({ type: 19, version: 3 }),
                          new Family({ type: 24, version: 1 }),
                          new Family({ type: 2, version: 1 }),
                          new Family({ type: 3, version: 1 }),
                          new Family({ type: 4, version: 1 }),
                          new Family({ type: 6, version: 1 }),
                          new Family({ type: 7, version: 1 }),
                          new Family({ type: 8, version: 1 }),
                          new Family({ type: 9, version: 1 }),
                          new Family({ type: 10, version: 1 }),
                          new Family({ type: 11, version: 1 }),
                          new Family({ type: 15, version: 1 }),
                          new Family({ type: 16, version: 1 }),
                        ],
                      },
                    }).ToBuffer()
                  )
                );
                return;
              }
              case Types.THIRTY: {
                // set status request.
                return;
              }
            }
            break;
          }
          case FoodGroups.TWO: {
            // location services
            switch (snac.type) {
              case Types.TWO: {
                // location rights request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.TWO,
                      type: Types.THREE,
                      flags: 0,
                      requestId: snac.requestId,
                      parameters: [
                        new Parameter({
                          type: ParameterTypes.ONE,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(1024)),
                        }),
                        new Parameter({
                          type: ParameterTypes.TWO,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(18)),
                        }),
                        new Parameter({
                          type: ParameterTypes.FIVE,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(128)),
                        }),
                        new Parameter({
                          type: ParameterTypes.THREE,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(10)),
                        }),
                        new Parameter({
                          type: ParameterTypes.FOUR,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(4096)),
                        }),
                      ],
                    }).ToBuffer()
                  )
                );
                return;
              }
              case Types.FOUR: {
                // user directory location information update request.
                snac.parameters.forEach((item) => {
                  if (session.user) {
                    switch (item.type) {
                      case ParameterTypes.ONE:
                        session.user.ProfileEncoding = Util.Bit.BufferToString(item.data as Buffer);
                        break;
                      case ParameterTypes.TWO:
                        session.user.Profile = item.data as Buffer;
                        break;
                      case ParameterTypes.THREE:
                        session.user.AwayMessageEncoding = Util.Bit.BufferToString(item.data as Buffer);
                        break;
                      case ParameterTypes.FOUR:
                        session.user.AwayMessage = Util.Bit.BufferToString(item.data as Buffer);
                        break;
                      case ParameterTypes.FIVE:
                        session.user.Capabilities = item.data as Buffer;
                        break;
                      case ParameterTypes.SIX:
                        session.user.Certs = item.data as Buffer;
                        break;
                    }
                  }
                });
                if (session.user) {
                  await session.user.updateStatus(session, _sessions, SendData);
                }
                return;
              }
              case Types.NINE: {
                // directory update request.
                // just ack. maybe we'll record directory later.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.TWO,
                      type: Types.TEN,
                      flags: 0,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(Util.Bit.UInt16ToBytes(1))
                );
                return;
              }
              case Types.ELEVEN: {
                // directory information request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.TWO,
                      type: Types.TWELVE,
                      flags: 0,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(Util.Bit.UInt16ToBytes(1), Util.Bit.UInt16ToBytes(0))
                );
                return;
              }
              case Types.FIFTEEN: {
                // directory update interests request.
                // just ack. maybe we'll record directory interests later.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.TWO,
                      type: Types.FIFTEEN,
                      flags: 0,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(Util.Bit.UInt16ToBytes(1))
                );
                return;
              }
              case Types.TWENTYONE: {
                // locate directory info request.
                const userInfo = _sessions.item({
                  screenName: Util.Strings.TrimData(snac.screenName),
                });
                if (userInfo?.user) {
                  const flagParameters = [
                    new Parameter({
                      type: ParameterTypes.ONE,
                      data: Util.Bit.BytesToBuffer(
                        Util.Bit.UInt32ToBytes(
                          Util.Bit.UserClass(
                            userInfo.user.Class,
                            userInfo.user.AwayMessage && userInfo.user.AwayMessage.length ? true : false
                          )
                        )
                      ),
                    }),
                    new Parameter({
                      type: ParameterTypes.FIFTEEN,
                      data: Util.Bit.BytesToBuffer(
                        Util.Bit.UInt32ToBytes(Util.Dates.GetTimestamp() - userInfo.user.SignedOnTimestamp.getTime())
                      ),
                    }),
                    new Parameter({
                      type: ParameterTypes.THREE,
                      data: Util.Bit.BytesToBuffer(Util.Bit.UInt32ToBytes(userInfo.user.SignedOnTimestamp.getTime())),
                    }),
                  ];
                  if (
                    Util.Bit.BufferToUInt32(Util.Bit.BytesToBuffer(snac.requestFlags)) & 0x01 &&
                    userInfo.user.Profile
                  ) {
                    flagParameters.push(
                      new Parameter({
                        type: ParameterTypes.ONE,
                        data: Util.Bit.StringToBuffer(userInfo.user.ProfileEncoding),
                      })
                    );
                    flagParameters.push(
                      new Parameter({
                        type: ParameterTypes.TWO,
                        data: userInfo.user.Profile,
                      })
                    );
                  }
                  if (
                    Util.Bit.BufferToUInt32(Util.Bit.BytesToBuffer(snac.requestFlags)) & 0x02 &&
                    userInfo.user.AwayMessage &&
                    userInfo.user.AwayMessage.length
                  ) {
                    flagParameters.push(
                      new Parameter({
                        type: ParameterTypes.THREE,
                        data: Util.Bit.StringToBuffer(userInfo.user.AwayMessageEncoding),
                      })
                    );
                    flagParameters.push(
                      new Parameter({
                        type: ParameterTypes.FOUR,
                        data: Util.Bit.StringToBuffer(userInfo.user.AwayMessage),
                      })
                    );
                  }
                  if (
                    Util.Bit.BufferToUInt32(Util.Bit.BytesToBuffer(snac.requestFlags)) & 0x04 &&
                    userInfo.user.Capabilities
                  ) {
                    flagParameters.push(
                      new Parameter({
                        type: ParameterTypes.FIVE,
                        data: userInfo.user.Capabilities,
                      })
                    );
                  }
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: FoodGroups.TWO,
                        type: Types.SIX,
                        flags: 0,
                        requestId: snac.requestId,
                        extensions: {
                          formattedScreenName: userInfo.user.FormattedScreenName,
                        },
                        parameters: flagParameters,
                      }).ToBuffer()
                    )
                  );
                  return;
                }
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.TWO,
                      type: Types.ONE,
                      flags: 0,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(Util.Bit.UInt16ToBytes(4))
                );
                return;
              }
            }
            break;
          }
          case FoodGroups.THREE: {
            // buddy list management service
            switch (snac.type) {
              case Types.TWO: // buddy rights request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.THREE,
                      type: Types.THREE,
                      flags: 0,
                      requestId: snac.requestId,
                      parameters: [
                        new Parameter({
                          type: ParameterTypes.TWO,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(2000)),
                        }),
                        new Parameter({
                          type: ParameterTypes.ONE,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(220)),
                        }),
                        new Parameter({
                          type: ParameterTypes.FOUR,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(32)),
                        }),
                      ],
                    }).ToBuffer()
                  )
                );
                return;
            }
            break;
          }
          case FoodGroups.FOUR: {
            // icbm service
            switch (snac.type) {
              case Types.TWO: {
                // update icbm params request.
                return;
              }
              case Types.FOUR: {
                // request icbm parameters.
                //console.log("SUPER SNAC", snac);
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: 0x0004,
                      type: 0x0005,
                      flags: 0,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(
                    Util.Bit.UInt16ToBytes(2),
                    Util.Bit.UInt32ToBytes(3),
                    Util.Bit.UInt16ToBytes(512),
                    Util.Bit.UInt16ToBytes(999),
                    Util.Bit.UInt16ToBytes(999),
                    Util.Bit.UInt16ToBytes(0),
                    Util.Bit.UInt16ToBytes(1000)
                  )
                );
                return;
              }
              case Types.SIX: {
                // incoming icbm
                const existingSession = _sessions.item({
                  screenName: snac.screenName,
                });
                if (existingSession) {
                  const ack = snac.parameters.find((item) => {
                    return item.type === ParameterTypes.THREE;
                  });
                  if (ack) {
                    // SendData(session, snac.requestId, 2,
                    // Util.Bit.BufferToBytes(new SNAC({
                    //     foodGroup: FoodGroups.FOUR,
                    //     type: Types.TWELVE,
                    //     flags: 0,
                    //     requestId: snac.requestId
                    // }).ToBuffer()).concat(
                    //     snac.cookie,
                    //     snac.channel,
                    //     Util.Bit.UInt8ToBytes(existingSession.user.FormattedScreenName.length),
                    //     Util.Bit.StringToBytes(existingSession.user.FormattedScreenName)
                    // ));
                  }
                  const frags = snac.parameters
                    .map((item) => {
                      if (item.data instanceof Buffer) {
                        return Util.Bit.BytesToBuffer([]);
                      }

                      return item.data
                        .filter((i) => {
                          return i instanceof Fragment;
                        })
                        .map((i) => {
                          return i.ToBuffer();
                        })
                        .flat();
                    })
                    .flat();
                  //existingSession = overwriteSnacData(existingSession, '<HTML><BODY BGCOLOR="#ffffff"><FONT LANG="0">12345</FONT></BODY></HTML>')

                  _existingSession = existingSession;
                  _snac = snac;
                  _session = session;
                  ready = true;
                  if (frags) {
                    console.log(frags.slice(0, 15));
                  }

                  SendData(
                    existingSession,
                    0,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: FoodGroups.FOUR,
                        type: Types.SEVEN,
                        flags: 0,
                        requestId: 0,
                        extensions: {
                          cookie: snac.cookie,
                          channel: snac.channel,
                          formattedScreenName: session.user?.FormattedScreenName,
                          warningLevel: 0,
                        },
                        parameters:
                          snac.channel === 1
                            ? [
                                new Parameter({
                                  type: ParameterTypes.TWO,
                                  data: Buffer.concat(frags),
                                }),
                              ]
                            : snac.channel === 2
                              ? [
                                  new Parameter({
                                    type: ParameterTypes.FIVE,
                                    data: snac.parameters.find((item) => {
                                      return item.type === ParameterTypes.FIVE;
                                    })?.data as Buffer,
                                  }),
                                ]
                              : [],
                      }).ToBuffer()
                    ),
                    true
                  );
                  return;
                }

                // SendData(session, snac.requestId, 2, new SNAC({
                //     foodGroup: 0x04,
                //     type: 0x01,
                //     flags: 0,
                //     requestId: snac.requestId,
                //     extensions: {
                //         errorId: 4
                //     }
                // }).ToBytes());
                return;
              }
            }
            break;
          }
          case FoodGroups.FIVE: {
            // advertisement service
            return;
          }
          case FoodGroups.SIX: {
            // invitation service
            break;
          }
          case FoodGroups.SEVEN: {
            // administrative service
            switch (snac.type) {
              case Types.TWO: {
                // admin information request.
                if (
                  snac.parameters.find((item) => {
                    return item.type === ParameterTypes.ONE;
                  })
                ) {
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: FoodGroups.SEVEN,
                        type: Types.THREE,
                        flags: 0,
                        requestId: snac.requestId,
                        parameters: [
                          new Parameter({
                            type: ParameterTypes.ONE,
                            data: Util.Bit.StringToBuffer(session.user?.FormattedScreenName),
                          }),
                        ],
                        extensions: {
                          permissions: 3,
                        },
                      }).ToBuffer()
                    )
                  );
                }
                if (
                  snac.parameters.find((item) => {
                    return item.type === ParameterTypes.SEVENTEEN;
                  })
                ) {
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: FoodGroups.SEVEN,
                        type: Types.THREE,
                        flags: 0,
                        requestId: snac.requestId,
                        parameters: [
                          new Parameter({
                            type: ParameterTypes.SEVENTEEN,
                            data: Util.Bit.StringToBuffer(session.user?.EmailAddress),
                          }),
                        ],
                        extensions: {
                          permissions: 3,
                        },
                      }).ToBuffer()
                    )
                  );
                }
                if (
                  snac.parameters.find((item) => {
                    return item.type === ParameterTypes.NINETEEN;
                  })
                ) {
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: FoodGroups.SEVEN,
                        type: Types.THREE,
                        flags: 0,
                        requestId: snac.requestId,
                        parameters: [
                          new Parameter({
                            type: ParameterTypes.NINETEEN,
                            data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(3)),
                          }),
                        ],
                      }).ToBuffer()
                    )
                  );
                }
                return;
              }
              case Types.FOUR: {
                // admin information update request.
                const buffer: Buffer[] = [];
                if (
                  snac.parameters.find((item) => {
                    return item.type === ParameterTypes.ONE;
                  })
                ) {
                  const parameter = snac.parameters.find((item) => {
                    return item.type === ParameterTypes.ONE;
                  })?.data as Buffer;
                  if (
                    session.user &&
                    Util.Strings.TrimData(Util.Bit.BufferToString(parameter)) === session.user.ScreenName &&
                    parameter.length <= 18
                  ) {
                    session.user.FormattedScreenName = Util.Bit.BufferToString(parameter).trim();
                    buffer.push(
                      new Buffer([
                        Util.Bit.UInt16ToBytes(0x03),
                        Util.Bit.UInt16ToBytes(0x01),
                        new Parameter({
                          type: ParameterTypes.ONE,
                          data: Util.Bit.StringToBuffer(Util.Bit.BufferToString(parameter).trim()),
                        }).ToBuffer(),
                      ])
                    );
                    await session.user.updateStatus(session, _sessions, SendData);
                  } else {
                    buffer.push(
                      new Buffer([
                        Util.Bit.UInt16ToBytes(0x03),
                        Util.Bit.UInt16ToBytes(0x03),
                        new Parameter({
                          type: ParameterTypes.ONE,
                          data: [],
                        }).ToBuffer(),
                        new Parameter({
                          type: ParameterTypes.FOUR,
                          data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/'),
                        }).ToBuffer(),
                        new Parameter({
                          type: ParameterTypes.EIGHT,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(0x0b)),
                        }).ToBuffer(),
                      ])
                    );
                  }
                }
                const parameter = snac.parameters.find((item) => {
                  return item.type === ParameterTypes.SEVENTEEN;
                })?.data as Buffer;
                if (parameter && session.user) {
                  if (
                    Util.Bit.BufferToString(parameter).indexOf('@') > -1 &&
                    Util.Bit.BufferToString(parameter).indexOf('.') > -1
                  ) {
                    session.user.EmailAddress = Util.Bit.BufferToString(parameter).trim();
                    buffer.push(
                      new Buffer([
                        Util.Bit.UInt16ToBytes(0x03),
                        Util.Bit.UInt16ToBytes(0x01),
                        new Parameter({
                          type: 0x11,
                          data: Util.Bit.StringToBuffer(Util.Bit.BufferToString(parameter).trim()),
                        }).ToBuffer(),
                      ])
                    );
                  } else {
                    buffer.push(
                      new Buffer([
                        Util.Bit.UInt16ToBytes(0x03),
                        Util.Bit.UInt16ToBytes(0x03),
                        new Parameter({
                          type: ParameterTypes.SEVENTEEN,
                          data: [],
                        }).ToBuffer(),
                        new Parameter({
                          type: ParameterTypes.FOUR,
                          data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/'),
                        }).ToBuffer(),
                        new Parameter({
                          type: ParameterTypes.EIGHT,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(0x0b)),
                        }).ToBuffer(),
                      ])
                    );
                  }
                }
                if (
                  snac.parameters.find((item) => {
                    return item.type === ParameterTypes.NINETEEN;
                  })
                ) {
                  buffer.push(
                    new Buffer([
                      Util.Bit.UInt16ToBytes(0x01),
                      Util.Bit.UInt16ToBytes(0x03),
                      new Parameter({
                        type: ParameterTypes.NINETEEN,
                        data: [],
                      }).ToBuffer(),
                      new Parameter({
                        type: ParameterTypes.FOUR,
                        data: Util.Bit.StringToBuffer('https://www.lwrca.se/owaim/'),
                      }).ToBuffer(),
                      new Parameter({
                        type: ParameterTypes.EIGHT,
                        data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(0x10)),
                      }).ToBuffer(),
                    ])
                  );
                }
                if (session.user) {
                  await session.user.updateAdminInfo();
                }
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.SEVEN,
                      type: Types.FIVE,
                      flags: 0,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(...buffer.map((b) => Util.Bit.BufferToBytes(b)))
                );
                if (session.user) {
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: 0x0001,
                        type: 0x000f,
                        flags: 0,
                        requestId: snac.requestId,
                        parameters: [
                          new Parameter({
                            type: ParameterTypes.ONE,
                            data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                          }),
                          new Parameter({
                            type: ParameterTypes.SIX,
                            data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                          }),
                          new Parameter({
                            type: ParameterTypes.FIFTEEN,
                            data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                          }),
                          new Parameter({
                            type: ParameterTypes.THREE,
                            data: Util.Bit.BytesToBuffer(Util.Bit.UInt32ToBytes(Util.Dates.GetTimestamp())),
                          }),
                          new Parameter({
                            type: ParameterTypes.TEN,
                            data: Util.Bit.BytesToBuffer(
                              session.socket?.remoteAddress
                                ?.split('.')
                                .map((item) => {
                                  return Util.Bit.UInt8ToBytes(parseInt(item));
                                })
                                .flat() ?? [0, 0, 0, 0]
                            ),
                          }),
                          new Parameter({
                            type: ParameterTypes.THIRTY,
                            data: Util.Bit.BytesToBuffer([0, 0, 0, 0]),
                          }),
                          new Parameter({
                            type: 0x05,
                            data: Util.Bit.BytesToBuffer(Util.Bit.UInt32ToBytes(session.user.CreationDate.getTime())),
                          }),
                          new Parameter({
                            type: 0x0c,
                            data: Util.Bit.BytesToBuffer([
                              0xae, 0x44, 0xbe, 0xa5, 0x00, 0x00, 0x16, 0x44, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            ]),
                          }),
                        ],
                        extensions: {
                          formattedScreenName: session.user.FormattedScreenName,
                        },
                      }).ToBuffer()
                    )
                  );
                }
                return;
              }
            }
            break;
          }
          case FoodGroups.EIGHT: {
            // popup notices service
            return;
          }
          case FoodGroups.NINE: {
            // privacy management service
            switch (snac.type) {
              case Types.TWO: {
                // privacy rights request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.NINE,
                      type: Types.THREE,
                      flags: 0,
                      requestId: snac.requestId,
                      parameters: [
                        new Parameter({
                          type: ParameterTypes.TWO,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(220)),
                        }),
                        new Parameter({
                          type: ParameterTypes.ONE,
                          data: Util.Bit.BytesToBuffer(Util.Bit.UInt16ToBytes(220)),
                        }),
                      ],
                    }).ToBuffer()
                  )
                );
                return;
              }
            }
            break;
          }
          case FoodGroups.TEN: {
            // user lookup service
            return;
          }
          case FoodGroups.ELEVEN: {
            // usage stats service
            return;
          }
          case FoodGroups.TWELVE: {
            // translation service
            return;
          }
          case FoodGroups.FIFTEEN: {
            // directory user search
            return;
          }
          case FoodGroups.SIXTEEN: {
            // server-stored buddy icons service
            return;
          }
          case FoodGroups.NINETEEN: {
            // server side information service
            switch (snac.type) {
              case Types.TWO: {
                // feedbag rights request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.NINETEEN,
                      type: Types.THREE,
                      flags: 0,
                      requestId: snac.requestId,
                      parameters: [
                        new Parameter({
                          type: 0x04,
                          data: Util.Bit.BytesToBuffer([
                            0x01, 0x90, 0x00, 0x3d, 0x00, 0xc8, 0x00, 0xc8, 0x00, 0x01, 0x00, 0x01, 0x00, 0x96, 0x00,
                            0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x32, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01, 0x00,
                            0x28, 0x00, 0x01, 0x00, 0x0a, 0x00, 0xc8,
                          ]),
                        }),
                        new Parameter({
                          type: ParameterTypes.TWO,
                          data: Util.Bit.BytesToBuffer([0x00, 0xfe]),
                        }),
                        new Parameter({
                          type: ParameterTypes.THREE,
                          data: Util.Bit.BytesToBuffer([0x01, 0xfc]),
                        }),
                        new Parameter({
                          type: ParameterTypes.FIVE,
                          data: Util.Bit.BytesToBuffer([0x00, 0x64]),
                        }),
                        new Parameter({
                          type: ParameterTypes.SIX,
                          data: Util.Bit.BytesToBuffer([0x00, 0x61]),
                        }),
                        new Parameter({
                          type: ParameterTypes.SEVEN,
                          data: Util.Bit.BytesToBuffer([0x00, 0xc8]),
                        }),
                        new Parameter({
                          type: ParameterTypes.EIGHT,
                          data: Util.Bit.BytesToBuffer([0x00, 0x0a]),
                        }),
                        new Parameter({
                          type: ParameterTypes.NINE,
                          data: Util.Bit.BytesToBuffer([0x00, 0x06, 0x0f, 0x22]),
                        }),
                        new Parameter({
                          type: ParameterTypes.TEN,
                          data: Util.Bit.BytesToBuffer([0x00, 0x06, 0x0f, 0x0e]),
                        }),
                      ],
                    }).ToBuffer()
                  )
                );
                return;
              }
              case Types.FOUR: {
                // feedbag request.
                const buddyList = await session.user?.getFeedbagBuddyList();
                const timeStamp = await session.user?.getFeedbagTimestamp();
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.NINETEEN,
                      type: Types.SIX,
                      flags: 0,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(
                    Util.Bit.UInt8ToBytes(0),
                    Util.Bit.UInt16ToBytes(buddyList?.length ?? 0),
                    ...(buddyList?.map((item) =>
                      Util.Bit.BufferToBytes(
                        new SSI({
                          name: item.Name,
                          groupId: item.GroupID,
                          itemId: item.BuddyID,
                          classId: item.ClassID,
                          attributes: Util.Bit.BufferToBytes(item.Attributes),
                        }).ToBuffer()
                      )
                    ) ?? []),
                    Util.Bit.UInt32ToBytes(new Date(timeStamp ?? 0).getTime())
                  )
                );
                return;
              }
              case Types.FIVE: {
                // feedbag request if modified.
                const date = Util.Bit.BytesToUInt32(snac.date.getTime());
                const count = Util.Bit.BufferToUInt16(snac.count);
                const buddyList = await session.user?.getFeedbagBuddyList();
                const timeStamp = await session.user?.getFeedbagTimestamp();
                if (timeStamp != date && buddyList?.length != count) {
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: FoodGroups.NINETEEN,
                        type: Types.SIX,
                        flags: 0,
                        requestId: snac.requestId,
                      }).ToBuffer()
                    ).concat(
                      Util.Bit.UInt8ToBytes(0),
                      Util.Bit.UInt16ToBytes(buddyList?.length ?? 0),
                      ...(buddyList?.map((item) =>
                        Util.Bit.BufferToBytes(
                          new SSI({
                            name: item.Name,
                            groupId: item.GroupID,
                            itemId: item.BuddyID,
                            classId: item.ClassID,
                            attributes: Util.Bit.BufferToBytes(item.Attributes),
                          }).ToBuffer()
                        )
                      ) ?? []),
                      Util.Bit.UInt32ToBytes(timeStamp),
                      Util.Bit.UInt32ToBytes(date + 2588)
                    )
                  );
                } else {
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    Util.Bit.BufferToBytes(
                      new SNAC({
                        foodGroup: FoodGroups.NINETEEN,
                        type: Types.FIFTEEN,
                        flags: 0,
                        requestId: snac.requestId,
                      }).ToBuffer()
                    ).concat(snac.date, snac.count)
                  );
                }
                return;
              }
              case Types.SEVEN: {
                // feedbag in use.
                return;
              }
              case Types.EIGHT: {
                // feedbag add request.
                var _buffer = [];
                if (snac.items) {
                  for (const item of snac.items) {
                    const b = await session.user.addFeedbagItem(
                      item.name,
                      item.groupId,
                      item.itemId,
                      item.classId,
                      item.attributes
                    );
                    _buffer.push(b ? Util.Bit.BufferBytes([0x00, 0x00]) : Util.Bit.BufferBytes([0x00, 0x0a]));
                  }
                }
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.NINETEEN,
                      type: Types.FOURTEEN,
                      flags: 0x8000,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(_buffer.flat())
                );
                return;
              }
              case Types.NINE: {
                // feedbag update request.
                var _buffer = [];
                if (snac.items) {
                  for (const item of snac.items) {
                    const b = await session.user.updateFeedbagItem(
                      item.name,
                      item.groupId,
                      item.itemId,
                      item.classId,
                      item.attributes
                    );
                    _buffer.push(b ? Util.Bit.BufferBytes([0x00, 0x00]) : Util.Bit.BufferBytes([0x00, 0x0a]));
                  }
                }
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.NINETEEN,
                      type: Types.FOURTEEN,
                      flags: 0x8000,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(_buffer.flat())
                );
                return;
              }
              case Types.TEN: {
                // feedbag delete request.
                var _buffer = [];
                if (snac.items) {
                  for (const item of snac.items) {
                    const b = await session.user.deleteFeedbagItem(
                      item.name,
                      item.groupId,
                      item.itemId,
                      item.classId,
                      item.attributes
                    );
                    _buffer.push(b ? Util.Bit.BufferBytes([0x00, 0x00]) : Util.Bit.BufferBytes([0x00, 0x0a]));
                  }
                }
                SendData(
                  session,
                  snac.requestId,
                  2,
                  Util.Bit.BufferToBytes(
                    new SNAC({
                      foodGroup: FoodGroups.NINETEEN,
                      type: Types.FOURTEEN,
                      flags: 0x8000,
                      requestId: snac.requestId,
                    }).ToBuffer()
                  ).concat(_buffer.flat())
                );
                return;
              }
              case Types.EIGHTEEN: {
                await session.user.updateFeedbagMeta();
                await session.user.updateStatus(session, _sessions, SendData);
              }
            }
            break;
          }
          case FoodGroups.TWENTYONE: {
            // ICQ specific extensions service
            return;
          }
          case FoodGroups.TWENTYTHREE: {
            // authorization/registration service
            return;
          }
          case FoodGroups.TWENTYFOUR: {
            // email
            return;
          }
        }
        // All other SNACs
        //console.log('BOS unhandled', snac)
        return;
      }
      case 4: {
        // disconnect
        return;
      }
    }
  }
});
bosServer
  .listen(_options.bosPort, _options.ip)
  .on('listening', () => {
    console.log('BOS socket listening on', bosServer.address());
  })
  .on('error', (err) => {
    console.log('BOS server socket error:', err);
  });

const aosServer = Net.createServer((socket) => {
  const session: Session = {
    sequence: 0,
    socket: socket,
    buffer: Util.Bit.BytesToBuffer([]),
    groupId: -1,
    cookie: '',
    services: [],
    ticket: '',
  };
  session.socket.on('error', (err) => {
    console.log('<!> AOS server socket error:', err);
  });
  session.socket.on('end', () => {
    session.socket.destroy();
    session.sequence = 0;
    if (session.chat) {
      // remove user from users list.
      if (session.parent?.user) {
        session.chat.users.splice(session.chat.users.indexOf(session.parent.user), 1);
      }
      // remove session from chat.
      session.chat.sessions.splice(session.chat.sessions.indexOf(session), 1);
      // send leave.
      session.chat.sessions.forEach((item) => {
        SendData(
          item,
          0,
          2,
          new SNAC({
            foodGroup: FoodGroups.FOURTEEN,
            type: SNACTypes.FOUR,
            flags: 0,
            requestId: 0,
            parameters: [
              new Parameter({
                type: ParameterTypes.ONE,
                data: Util.Bit.BytesToBuffer(Util.Bit.UInt32ToBytes(0x0000)),
              }),
              new Parameter({
                type: ParameterTypes.FIFTEEN,
                data: Util.Bit.BytesToBuffer(Util.Bit.UInt32ToBytes(0x0000)),
              }),
              new Parameter({
                type: ParameterTypes.THREE,
                data: Util.Bit.BytesToBuffer(Util.Bit.UInt32ToBytes(0x0000)),
              }),
            ],
            extensions: {
              formattedScreenName: session.parent.user?.FormattedScreenName,
              warningLevel: 0,
            },
          }).ToBuffer()
        );
      });
    }
    // remove from services.
    if (session.parent) {
      session.parent.services.splice(session.parent.services.indexOf(session), 1);
    }
    // remove from sessions.
    _sessions.remove(session);
    delete session;
  });
  session.socket.on('data', async (data) => {
    session.buffer = { ...session.buffer, ...data };

    let endProcStream = false;
    if (session.buffer.length < 10) {
      return;
    }
    while (session.buffer.length > 0 && !endProcStream) {
      if (session.buffer.slice(0, 1)[0] !== 0x2a) {
        //console.log('<!> non FLAP packet recieved on BOS socket!');
        return;
      }
      const size = Util.Bit.BufferToUInt16(session.buffer.slice(4, 6));
      if (session.buffer.length >= 6 + size) {
        await ProcessRequest(
          session,
          session.buffer.subarray(0, 6),
          session.buffer.subarray(6, 6 + size),
          session.buffer.subarray(0, 6 + size)
        );
      } else {
        endProcStream = true;
      }
    }
  });
  SendData(session, 0, 1, Util.Constants._FLAP_VERSION);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async function ProcessRequest(session: Session, header, data, _bytes: Buffer) {
    // get FLAP header.
    const flap = new FLAP(header);
    switch (flap.channel) {
      case 1: {
        // auth
        if (data.length > 4) {
          const parameters = Parameter.GetParameters(0, 0, data.slice(4));
          const cookie = parameters.find((item) => {
            return item.type === 0x06;
          });
          if (cookie) {
            const existingSession = _sessions.item({ serviceCookie: Util.Bit.BytesToString(cookie.data) });
            if (existingSession) {
              const serviceSession = existingSession.services.find((item) => {
                return item.cookie === Util.Bit.BytesToString(cookie.data);
              });
              if (serviceSession) {
                session.parent = {
                  ...session,
                  ...serviceSession,
                };
                SendData(
                  session,
                  0,
                  2,
                  new SNAC({
                    foodGroup: 0x0001,
                    type: 0x0003,
                    flags: 0,
                    requestId: 0,
                    extensions: {
                      families: [1, 13, 14, 15, 16],
                    },
                  }).ToBuffer()
                );
                return;
              }
              SendData(session, 0, 4, []);
              return;
            }
            SendData(session, 0, 4, []);
            return;
          }
          SendData(session, 0, 4, []);
          return;
        }
        SendData(session, 0, 4, []);
        return;
      }
      case 2: {
        // snac
        // get SNAC packet
        const snac = new SNAC(data);
        //console.log('AOS', snac);
        switch (snac.foodGroup) {
          case 0x0001: // generic service controls
            switch (snac.type) {
              case 0x02: // client service ready
                SendData(
                  session,
                  snac.requestId,
                  2,
                  new SNAC({
                    foodGroup: 0x000d,
                    type: 0x0009,
                    flags: 0,
                    requestId: snac.requestId,
                  })
                    .ToBuffer()
                    .concat([
                      0x00, 0x02, 0x00, 0x01, 0x11, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x07, 0xd0, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x04, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x02, 0x00,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x02, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x06, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x02, 0x00,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x02, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x40, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x1a, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0b, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0d, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0e, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0f, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x14, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x40, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x1a, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8,
                    ])
                );
                if (session.groupId === 0x0e) {
                  //console.log("SFSDFSDFS")
                  session.chatCookie = session.cookie.split('.')[0];
                  const chats = _chatrooms.findNonExistantSession(session.parent.user, session.chatCookie);
                  if (chats && chats.length > 0) {
                    const chat = chats[0];
                    session.chat = chat;
                    chat.sessions.forEach((item) => {
                      SendData(
                        session,
                        0,
                        2,
                        new SNAC({
                          foodGroup: 0x000e,
                          type: 0x0003,
                          flags: 0,
                          requestId: 0,
                          parameters: [
                            new Parameter({ type: 0x01, data: Util.Bit.UInt32ToBytes(0x0000) }),
                            new Parameter({ type: 0x0f, data: Util.Bit.UInt32ToBytes(0x0000) }),
                            new Parameter({ type: 0x03, data: Util.Bit.UInt32ToBytes(0x0000) }),
                          ],
                          extensions: {
                            formattedScreenName: item.parent.user.FormattedScreenName,
                            warningLevel: 0,
                          },
                        }).ToBuffer()
                      );
                    });
                    chat.sessions.push(session);
                    chat.sessions.forEach((item) => {
                      SendData(
                        item,
                        0,
                        2,
                        new SNAC({
                          foodGroup: 0x000e,
                          type: 0x0003,
                          flags: 0,
                          requestId: 0,
                          parameters: [
                            new Parameter({ type: 0x01, data: Util.Bit.UInt32ToBytes(0x0000) }),
                            new Parameter({ type: 0x0f, data: Util.Bit.UInt32ToBytes(0x0000) }),
                            new Parameter({ type: 0x03, data: Util.Bit.UInt32ToBytes(0x0000) }),
                          ],
                          extensions: {
                            formattedScreenName: session.parent.user.FormattedScreenName,
                            warningLevel: 0,
                          },
                        }).ToBuffer()
                      );
                    });
                  }
                }
                return;
              case 0x06: // rate limits request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  new SNAC({
                    foodGroup: 0x0001,
                    type: 0x0007,
                    flags: 0,
                    requestId: snac.requestId,
                  })
                    .ToBuffer()
                    .concat(Util.Bit.UInt16ToBytes(0))
                );
                return;
              case 0x17: // service host version request.
                SendData(
                  session,
                  0,
                  2,
                  new SNAC({
                    foodGroup: 0x0001,
                    type: 0x0018,
                    flags: 0,
                    requestId: 0,
                    extensions: {
                      families: [
                        new Family({ type: 1, version: 4 }),
                        new Family({ type: 2, version: 1 }),
                        new Family({ type: 3, version: 1 }),
                        new Family({ type: 4, version: 1 }),
                        new Family({ type: 6, version: 1 }),
                        new Family({ type: 8, version: 1 }),
                        new Family({ type: 9, version: 1 }),
                        new Family({ type: 10, version: 1 }),
                        new Family({ type: 11, version: 1 }),
                        new Family({ type: 12, version: 1 }),
                        new Family({ type: 14, version: 1 }),
                        new Family({ type: 13, version: 1 }),
                        new Family({ type: 19, version: 5 }),
                        new Family({ type: 21, version: 2 }),
                        new Family({ type: 34, version: 1 }),
                        new Family({ type: 34, version: 1 }),
                        new Family({ type: 37, version: 1 }),
                      ],
                    },
                  }).ToBuffer()
                );
                return;
            }
            break;
          case 0x000d: // chat navigation service
            //console.log("CHAT ROOM 2", snac)

            switch (snac.type) {
              case 0x02: {
                // chatnav rights request.
                SendData(
                  session,
                  snac.requestId,
                  2,
                  new SNAC({
                    foodGroup: 0x000d,
                    type: 0x0009,
                    flags: 0,
                    requestId: snac.requestId,
                  })
                    .ToBuffer()
                    .concat([
                      0x00, 0x02, 0x00, 0x01, 0x11, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x07, 0xd0, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x04, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x02, 0x00,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x02, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x06, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x02, 0x00,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x27, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x02, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x40, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x1a, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0b, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0d, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0e, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x0f, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x40, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x32, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x03, 0x00, 0x3c, 0x00, 0x14, 0x00, 0x0a, 0x00, 0x03, 0x00,
                      0x01, 0x16, 0x00, 0x04, 0x00, 0x02, 0x40, 0x00, 0x00, 0xc9, 0x00, 0x02, 0x00, 0x44, 0x00, 0xca,
                      0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xd1, 0x00, 0x02, 0x07, 0xd0,
                      0x00, 0xd2, 0x00, 0x02, 0x00, 0x1a, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd5, 0x00, 0x01, 0x01, 0x00,
                      0xda, 0x00, 0x02, 0x00, 0xe8,
                    ])
                );
                return;
              }
              case 0x04: {
                //console.log("EXIST ROOM")

                const existingChat = _chatrooms.item({ cookie: Util.Bit.BytesToString(snac.cookie) });
                if (existingChat) {
                  existingChat.users.push(session.parent.user.ScreenName);
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    new SNAC({
                      foodGroup: 0x0d,
                      type: 0x09,
                      flags: 0,
                      requestId: snac.requestId,
                      parameters: [
                        new Parameter({ type: 0x02, data: Util.Bit.UInt8ToBytes(10) }),
                        new Parameter({
                          type: 0x04,
                          data: Util.Bit.UInt16ToBytes(existingChat.exchange).concat(
                            Util.Bit.UInt8ToBytes(existingChat.cookie.length),
                            Util.Bit.BufferBytes(existingChat.cookie),
                            Util.Bit.UInt16ToBytes(0),
                            Util.Bit.UInt8ToBytes(2),
                            Util.Bit.UInt16ToBytes(10),
                            [
                              new Parameter({ type: 0xd0, data: Util.Bit.UInt16ToBytes(3) }).ToBuffer(),
                              new Parameter({ type: 0xd1, data: Util.Bit.UInt16ToBytes(1024) }).ToBuffer(),
                              new Parameter({ type: 0xd2, data: Util.Bit.UInt16ToBytes(66) }).ToBuffer(),
                              new Parameter({ type: 0xd3, data: Util.Bit.BufferBytes(existingChat.name) }).ToBuffer(),
                              new Parameter({ type: 0xd5, data: Util.Bit.UInt8ToBytes(1) }).ToBuffer(),
                              new Parameter({
                                type: 0xcb,
                                data: Util.Bit.BufferBytes(existingChat.creator),
                              }).ToBuffer(),
                              new Parameter({ type: 0x03, data: Util.Bit.UInt8ToBytes(10) }).ToBuffer(),
                              new Parameter({ type: 0x04, data: Util.Bit.UInt8ToBytes(20) }).ToBuffer(),
                              new Parameter({ type: 0x02, data: Util.Bit.UInt16ToBytes(0) }).ToBuffer(),
                              new Parameter({
                                type: 0x05,
                                data: Util.Bit.UInt16ToBytes(existingChat.exchange).concat(
                                  Util.Bit.UInt8ToBytes(existingChat.cookie.length),
                                  Util.Bit.BufferBytes(existingChat.cookie),
                                  Util.Bit.UInt16ToBytes(0)
                                ),
                              }).ToBuffer(),
                            ].flat()
                          ),
                        }),
                      ],
                    }).ToBuffer()
                  );
                  return;
                }
                return;
              }
              case 0x08: {
                // create/join chat.
                //console.log("CHAT JOIN")

                const chatRoomName = snac.parameters.find((item) => {
                  return item.type === 0xd3;
                });
                const chatCharset = snac.parameters.find((item) => {
                  return item.type === 0xd6;
                });
                const chatLang = snac.parameters.find((item) => {
                  return item.type === 0xd7;
                });
                const existingChat = _chatrooms.item({ name: Util.Bit.BytesToString(chatRoomName.data) });
                if (existingChat) {
                  existingChat.users.push(session.parent.user.ScreenName);
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    new SNAC({
                      foodGroup: 0x0d,
                      type: 0x09,
                      flags: 0,
                      requestId: snac.requestId,
                      parameters: [
                        new Parameter({ type: 0x02, data: Util.Bit.UInt8ToBytes(10) }),
                        new Parameter({
                          type: 0x04,
                          data: Util.Bit.UInt16ToBytes(existingChat.exchange).concat(
                            Util.Bit.UInt8ToBytes(existingChat.cookie.length),
                            Util.Bit.BufferBytes(existingChat.cookie),
                            Util.Bit.UInt16ToBytes(0),
                            Util.Bit.UInt8ToBytes(2),
                            Util.Bit.UInt16ToBytes(10),
                            [
                              new Parameter({ type: 0xd0, data: Util.Bit.UInt16ToBytes(3) }).ToBuffer(),
                              new Parameter({ type: 0xd1, data: Util.Bit.UInt16ToBytes(1024) }).ToBuffer(),
                              new Parameter({ type: 0xd2, data: Util.Bit.UInt16ToBytes(66) }).ToBuffer(),
                              new Parameter({ type: 0xd3, data: Util.Bit.BufferBytes(existingChat.name) }).ToBuffer(),
                              new Parameter({ type: 0xd5, data: Util.Bit.UInt8ToBytes(1) }).ToBuffer(),
                              new Parameter({
                                type: 0xcb,
                                data: Util.Bit.BufferBytes(existingChat.creator),
                              }).ToBuffer(),
                              new Parameter({ type: 0x03, data: Util.Bit.UInt8ToBytes(10) }).ToBuffer(),
                              new Parameter({ type: 0x04, data: Util.Bit.UInt8ToBytes(20) }).ToBuffer(),
                              new Parameter({ type: 0x02, data: Util.Bit.UInt16ToBytes(0) }).ToBuffer(),
                              new Parameter({
                                type: 0x05,
                                data: Util.Bit.UInt16ToBytes(existingChat.exchange).concat(
                                  Util.Bit.UInt8ToBytes(existingChat.cookie.length),
                                  Util.Bit.BufferBytes(existingChat.cookie),
                                  Util.Bit.UInt16ToBytes(0)
                                ),
                              }).ToBuffer(),
                            ].flat()
                          ),
                        }),
                      ],
                    }).ToBuffer()
                  );
                  return;
                } else {
                  //console.log("CHAT ROOM")
                  const newRoom = _chatrooms.add({
                    exchange: Util.Bit.BufferToUInt16(snac.exchange),
                    cookie:
                      Util.Bit.BytesToString(snac.cookie) === 'create'
                        ? Util.Strings.GenerateChatCookie()
                        : Util.Bit.BytesToString(snac.cookie),
                    detailLevel: snac.detailLevel,
                    creator: session.parent.user.ScreenName,
                    name: Util.Bit.BytesToString(chatRoomName.data),
                    charset: Util.Bit.BytesToString(chatCharset.data),
                    lang: Util.Bit.BytesToString(chatLang.data),
                  });
                  newRoom.users.push(session.parent.user.ScreenName);
                  SendData(
                    session,
                    snac.requestId,
                    2,
                    new SNAC({
                      foodGroup: 0x0d,
                      type: 0x09,
                      flags: 0,
                      requestId: snac.requestId,
                      parameters: [
                        new Parameter({ type: 0x02, data: Util.Bit.UInt8ToBytes(10) }),
                        new Parameter({
                          type: 0x04,
                          data: Util.Bit.UInt16ToBytes(newRoom.exchange).concat(
                            Util.Bit.UInt8ToBytes(newRoom.cookie.length),
                            Util.Bit.BufferBytes(newRoom.cookie),
                            Util.Bit.UInt16ToBytes(0),
                            Util.Bit.UInt8ToBytes(2),
                            Util.Bit.UInt16ToBytes(10),
                            [
                              new Parameter({ type: 0xd0, data: Util.Bit.UInt16ToBytes(3) }).ToBuffer(),
                              new Parameter({ type: 0xd1, data: Util.Bit.UInt16ToBytes(1024) }).ToBuffer(),
                              new Parameter({ type: 0xd2, data: Util.Bit.UInt16ToBytes(66) }).ToBuffer(),
                              new Parameter({ type: 0xd3, data: Util.Bit.BufferBytes(newRoom.name) }).ToBuffer(),
                              new Parameter({ type: 0xd5, data: Util.Bit.UInt8ToBytes(1) }).ToBuffer(),
                              new Parameter({ type: 0xcb, data: Util.Bit.BufferBytes(newRoom.creator) }).ToBuffer(),
                              new Parameter({ type: 0x03, data: Util.Bit.UInt8ToBytes(10) }).ToBuffer(),
                              new Parameter({ type: 0x04, data: Util.Bit.UInt8ToBytes(20) }).ToBuffer(),
                              new Parameter({ type: 0x02, data: Util.Bit.UInt16ToBytes(0) }).ToBuffer(),
                              new Parameter({
                                type: 0x05,
                                data: Util.Bit.UInt16ToBytes(newRoom.exchange).concat(
                                  Util.Bit.UInt8ToBytes(newRoom.cookie.length),
                                  Util.Bit.BufferBytes(newRoom.cookie),
                                  Util.Bit.UInt16ToBytes(0)
                                ),
                              }).ToBuffer(),
                            ].flat()
                          ),
                        }),
                      ],
                    }).ToBuffer()
                  );
                  return;
                }
              }
            }
            break;
          case 0x000e: // chat service
            //console.log("CHAHHAHAT", snac)
            switch (snac.type) {
              case 0x05: {
                const userInfoBlock = new Parameter({
                  type: 0x03,
                  data: Util.Bit.UInt8ToBytes(session.parent.user.ScreenName.length).concat(
                    Util.Bit.BufferBytes(session.parent.user.ScreenName),
                    Util.Bit.UInt16ToBytes(0),
                    Util.Bit.UInt16ToBytes(3),
                    new Parameter({ type: 0x01, data: Util.Bit.UInt16ToBytes(0) }).ToBuffer(),
                    new Parameter({ type: 0x0f, data: Util.Bit.UInt32ToBytes(0) }).ToBuffer(),
                    new Parameter({ type: 0x03, data: Util.Bit.UInt32ToBytes(0) }).ToBuffer()
                  ),
                });
                const parameterMessageInformation = snac.parameters.find((item) => {
                  return item.type === 0x05;
                });
                // reflection ??
                SendData(
                  session,
                  snac.requestId,
                  2,
                  new SNAC({
                    foodGroup: 0x0e,
                    type: 0x06,
                    flags: 0,
                    requestId: snac.requestId,
                    extensions: {
                      cookie: snac.cookie,
                      channel: snac.channel,
                    },
                    parameters: [
                      userInfoBlock,
                      new Parameter({ type: 0x01, data: Util.Bit.UInt16ToBytes(32) }),
                      parameterMessageInformation,
                    ],
                  }).ToBuffer()
                );
                const userSessions = session.chat.sessions.filter((item) => {
                  return item.parent.user.ScreenName !== session.parent.user.ScreenName;
                });
                userSessions.forEach((userSession) => {
                  SendData(
                    userSession,
                    0,
                    2,
                    new SNAC({
                      foodGroup: 0x0e,
                      type: 0x06,
                      flags: 0,
                      requestId: 0,
                      extensions: {
                        cookie: snac.cookie,
                        channel: snac.channel,
                      },
                      parameters: [userInfoBlock, parameterMessageInformation],
                    }).ToBuffer()
                  );
                });
                return;
              }
            }
            break;
        }
        // All other SNACs
        //console.log('AOS unhandled ( group', session.groupId, ')', snac)
        return;
      }
      case 4: {
        // disconnect
        return;
      }
    }
  }
});
aosServer
  .listen(_options.aosPort, _options.ip)
  .on('listening', () => {
    console.log('AOS socket listening on', aosServer.address());
  })
  .on('error', (err) => {
    console.log('AOS server socket error:', err);
  });

// app.get('/test', (req, res) => {

//     if ( _existingSession.sequence) {
//         _existingSession.sequence + 1
//     }
//     let bufferBytes = [42,2,0,19,0,149,0,4,0,7,0,0,0,0,0,0,53,68,67,53,53,70,0,0,0,1,5,106,97,107,117,50,0,0,0,4,0,1,0,2,0,16,0,6,0,4,0,0,1,0,0,15,0,4,0,0,87,11,0,3,0,4,64,230,218,184,0,2,0,85,5,1,0,3,1,1,2,1,1,0,74,0,0,0,0,60,72,84,77,76,62,60,66,79,68,89,32,66,71,67,79,76,79,82,61,34,35,102,102,102,102,102,102,34,62,60,70,79,78,84,32,76,65,78,71,61,34,48,34,62,115,97,100,102,60,47,70,79,78,84,62,60,47,66,79,68,89,62,60,47,72,84,77,76,62]
//     _existingSession.socket.write(Buffer.from(bufferBytes));

//     res.send("ok")
// })

function createMessage(asciiString) {
  // Required bytes before the ASCII part

  const length = Buffer.byteLength(asciiString, 'utf8') + 4;
  const requiredBytes = [5, 1, 0, 3, 1, 1, 2, 1, 1, 0, length, 0, 0, 0, 0];
  console.log(requiredBytes);
  // Convert ASCII string to hexadecimal
  const hexString = asciiString
    .split('')
    .map((char) => {
      const hex = char.charCodeAt(0).toString(16);
      return hex.padStart(2, '0'); // Ensure 2 characters for each byte
    })
    .join('');

  // Convert the hex string to an array of bytes
  const hexBytes = [];
  for (let i = 0; i < hexString.length; i += 2) {
    hexBytes.push(parseInt(hexString.substr(i, 2), 16));
  }

  // Combine the required bytes with the hex bytes
  const resultArray = requiredBytes.concat(hexBytes);

  return resultArray;
}
app.get('/old/:text', (req, res) => {
  const text = req.params.text;
  const newMessage = createMessage(`<HTML><BODY BGCOLOR="#ffffff"><FONT LANG="0">${text}</FONT></BODY></HTML>`);

  const newSnac = new SNAC({
    foodGroup: 0x04,
    type: 0x07,
    flags: 0,
    requestId: 0,
    extensions: {
      cookie: Util.Bit.BytesToString(_snac.cookie),
      channel: Util.Bit.BufferToUInt16(_snac.channel),
      formattedScreenName: _session.user.FormattedScreenName,
      warningLevel: 0,
    },
    parameters: [
      Util.Bit.BufferToUInt16(_snac.channel) == 1
        ? new Parameter({ type: 0x02, data: newMessage })
        : Util.Bit.BufferToUInt16(_snac.channel) == 2
          ? new Parameter({
              type: 0x05,
              data: _snac.parameters.find((item) => {
                return item.type === 0x05;
              }).data,
            })
          : [],
    ],
  }).ToBuffer();

  SendData(_existingSession, 0, 2, newSnac);

  res.send('Hello World!');
});

app.post('/message', (req, res) => {
  const json = req.body;
  const { text, name } = json;
  const newMessage = createMessage(text);

  const newSnac = new SNAC({
    foodGroup: 0x04,
    type: 0x07,
    flags: 0,
    requestId: 0,
    extensions: {
      cookie: Util.Bit.BytesToString(_snac.cookie),
      channel: Util.Bit.BufferToUInt16(_snac.channel),
      formattedScreenName: name,
      warningLevel: 0,
    },
    parameters: [
      Util.Bit.BufferToUInt16(_snac.channel) == 1
        ? new Parameter({ type: 0x02, data: newMessage })
        : Util.Bit.BufferToUInt16(_snac.channel) == 2
          ? new Parameter({
              type: 0x05,
              data: _snac.parameters.find((item) => {
                return item.type === 0x05;
              }).data,
            })
          : [],
    ],
  }).ToBuffer();

  SendData(_existingSession, 0, 2, newSnac);

  res.send('Hello World!');
});

function sentAIMMessage(user, message) {
  const newMessage = createMessage(message);

  const newSnac = new SNAC({
    foodGroup: 0x04,
    type: 0x07,
    flags: 0,
    requestId: 0,
    extensions: {
      cookie: Util.Bit.BytesToString(_snac.cookie),
      channel: Util.Bit.BufferToUInt16(_snac.channel),
      formattedScreenName: user,
      warningLevel: 0,
    },
    parameters: [
      Util.Bit.BufferToUInt16(_snac.channel) == 1
        ? new Parameter({ type: 0x02, data: newMessage })
        : Util.Bit.BufferToUInt16(_snac.channel) == 2
          ? new Parameter({
              type: 0x05,
              data: _snac.parameters.find((item) => {
                return item.type === 0x05;
              }).data,
            })
          : [],
    ],
  }).ToBuffer();

  SendData(_existingSession, 0, 2, newSnac);
}

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
