export default class Options {
  ip = '127.0.0.1';
  aosPort = 5192;
  authPort = 5190;
  bosPort = 5191;

  constructor(params: string[]) {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const [node, script, ip, aosPort, authPort, bosPort] = params;

    if (ip) {
      this.ip = ip;
    }
    if (aosPort) {
      this.aosPort = parseInt(aosPort);
    }
    if (authPort) {
      this.authPort = parseInt(authPort);
    }
    if (bosPort) {
      this.bosPort = parseInt(bosPort);
    }
  }
}
