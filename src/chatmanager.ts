import { Session } from './sessionmanager.js';
import User from './user.js';

export type Chat = {
  exchange: number;
  cookie: string;
  instance: number;
  detailLevel: number;
  creator: string;
  name: string;
  charset: string;
  lang: string;
  users: User[];
  sessions: Session[];
};

class ChatManager {
  #collection: Chat[];

  constructor() {
    this.#collection = [];
  }
  add(item: Chat): Chat {
    const b = {
      ...structuredClone(item),
      ...({
        exchange: -1,
        cookie: '',
        instance: 0,
        detailLevel: 1,
        creator: '',
        name: '',
        charset: '',
        lang: '',
        users: [],
        sessions: [],
      } as Chat),
    };
    this.#collection.push(b);
    return b;
  }
  remove(item: Chat | string) {
    if (typeof item === 'string') {
      const a = this.#collection.find((r) => {
        return r.name === item;
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
  item({ name, cookie }: { name?: string; cookie?: string } = {}) {
    if (name) {
      return this.#collection.find((item) => {
        return item.name === name;
      });
    }
    if (cookie) {
      return this.#collection.find((item) => {
        return item.cookie === cookie;
      });
    }
    return null;
  }
  findNonExistantSession(user: User, cookie: string) {
    return this.#collection.filter((item) => {
      return item.cookie === cookie && item.users && item.users.indexOf(user) > -1;
    });
  }
  get collection() {
    return this.#collection;
  }
}

export default ChatManager;
