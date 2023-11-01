
# TIM
Originally OWAIM, we connected Twitch Chat to it and made any login work for now. The idea is to have other streamers be able to connect their chats and get messages as IMs, sub alerts and more.

## Why?
Since AIM's demise, I thought it would be a good idea to revive AIM (AOL Instant Messenger). This is similar to what Phoenix AIM provides but since their servers are closed source, I didn't want to use the service as I can't be sure that they aren't storing messages or doing other unsavory things.

AIM was my messenger of choice in its prime and the nostalgia factor alone drove me to create this project. Since emerging technologies such as Node.js are becoming more widely used, this project is a perfect candidate for server side messaging technology.

## How?
OSCAR (**O**pen **S**ystem for **C**ommunic**A**tion in **R**ealtime) is heavily documented across the web. Using example packet structures and known responses, I recreated the logic that was used to provide functioning Authorization, Data (BOS) and AOL Other Services (AOS) socket listeners.

## What?!?
AIM clients connect to an authorization server to exchange credentials. Once the credentials are validated, the authorization server sends an encoded ticket and the address and port to connect to for its Data connection.

This server software creates 3 listening sockets to provide Authorization, Data, and Transport services that AIM clients use for messaging.

The server keeps track of every session that connects and extends their properties with socket and user data as it moves through the Authorization, Data, and Transport sockets.

## What Works?
 - Authorization
 - Instant Messaging (ICBM)
 - Buddy Lists (Feedbag)
 - Chats
 - Profiles
 - Away Messages

<<<<<<< HEAD
## What Doesn't?
 - Directory services
 - Ad Services (this doesn't really seem like a bad thing though)
 - Email (POP)
 - Server Stored Buddy Icons and Meta Data
=======
```bash
git clone https://github.com/qwell/happy-ts.git
```

Navigate to the repo directory.

```bash
cd happy-ts
```

Install dependencies using Yarn.

```bash
yarn install
```

## Available Scripts

- `lint`: Run ESLint to check for code quality issues.

```bash
yarn lint
```

- `format`: Run Prettier to format the code.

```bash
yarn format
```

- `clean`: Clean up generated artifacts (like the `dist/` directory).

```bash
yarn clean
```

- `build`: Compile TypeScript files and output in the `dist/` directory.

```bash
yarn build
```

- `start`: Execute the compiled `dist/index.js`.

```bash
yarn start
```

- `test`: Execute tests with Vitest.

```bash
yarn test
```

## Contributing

If you'd like to contribute, pull requests and issues are always appreciated.

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## TODO

- Add Yarn workspaces/monorepo support (written, not yet committed).
>>>>>>> 97c5425 (Add Vitest to documentation.)
