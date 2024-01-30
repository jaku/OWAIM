export default class Options {
  ip = '127.0.0.1';
  aosPort = 5192;
  authPort = 5190;
  bosPort = 5191;

  constructor(params: Options) {
    this.ip = params.ip;
    this.aosPort = params.aosPort;
    this.authPort = params.authPort;
    this.bosPort = params.bosPort;
  }
}
