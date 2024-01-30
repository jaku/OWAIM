import Util from './util.js';
import User from './user.js';

import Net from 'net';
import { Chat } from './chatmanager.js';

export type SessionServices = {
  groupId: number;
  cookie: string;
};

export type Session = {
  chatCookie: string;
  parent?: Session;
  chat?: Chat;
  buffer: Buffer;
  socket: Net.Socket;
  user?: User;
  sequence: number;
  groupId: number;
  cookie: string;
  services: SessionServices[];
  ticket: string;
};

class SessionManager {
  #collection: Session[];
  constructor() {
    this.#collection = [];
  }

  add(item: Session) {
    const b: Session = {
      ...{
        user: undefined,
        sequence: 0,
        groupId: -1,
        buffer: Util.Bit.BytesToBuffer([]),
        socket: new Net.Socket(),
      },
      ...structuredClone(item),
    };
    this.#collection.push(b);
    return b;
  }

  remove(item: string | Session) {
    if (typeof item === 'string') {
      const a = this.#collection.find((i) => {
        return i.user && i.user.ScreenName === item;
      });
      if (a) {
        this.#collection.splice(this.#collection.indexOf(a), 1);
      }

      return this;
    }

    if (this.#collection.indexOf(item) > -1) {
      this.#collection.splice(this.#collection.indexOf(item), 1);
    }

    return this;
  }

  item(args: { screenName?: string; ticket?: string; cookie?: string; serviceCookie?: string }) {
    return this.#collection.find((item) => {
      if (args.screenName) {
        return item.user?.ScreenName === Util.Strings.TrimData(args.screenName);
      } else if (args.ticket) {
        return item.ticket === args.ticket;
      } else if (args.cookie) {
        return item.cookie === args.cookie;
      } else if (args.serviceCookie) {
        return item.services
          ? item.services.find(function (service) {
              return service.cookie === args.serviceCookie;
            })
          : false;
      } else {
        return null;
      }
    });
  }

  get collection() {
    return this.#collection;
  }
}

export default SessionManager;
