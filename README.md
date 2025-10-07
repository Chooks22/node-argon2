# node-argon2

Password Hashing Using NodeJS' Built-in Argon2 Implementation.

## Installation

> Support for `crypto.argon2` was implemented in NodeJS 24.7.0,
make sure you have the same or later version.

```sh
npm i node-argon2
```

## Usage

```ts
import { hash, verify } from 'node-argon2';

const password = 'correct-horse-battery-staple';

const passwordHash = await hash(password);
console.log(await verify({ password, hash: passwordHash })); // true
```

The default algorithm is `argon2id` with parameters `memory=9216`,
`iterations=4`, `parallelism=1`. You can change these by passing
them as parameters to `hash()`:

```ts
const passwordhash = await hash(
  password,
  {
    memory: 19_456,
    iterations: 2,
    parallelism: 1,
  },
  'argon2d',
);
```

The package is also fully compatible with `better-auth`:

```ts
import { betterAuth } from 'better-auth';
import * as password from 'node-argon2';

export const auth = betterAuth({
  // ...rest of the options
  emailAndPassword: {
    password,
  },
});
```
