# Tulip 2FA

A simple 2FA library for Node.js

## Usage

-   Generate a random 2FA secret.

```ts
import { generateSecret } from 'tulip-2fa';

// Default usage - Generate a base32-encoded secret of 20 bytes (recommended by RFC4226 for TOTP and HOTP)
console.log(generateSecret());

// Advanced usage - Generate a base32-encoded secret of x bytes.
console.log(generateSecret(x));
```

-   Generate the 2FA code using a secret.

```ts
import { generateCode } from 'tulip-2fa';

const secret = '<SOME-BASE32-ENCODED-SECRET>';

// Default usage.
console.log(generateCode(secret));

// Advanced usage.
console.log(generateCode({ secret, step: 30, length: 6, algorithm: 'sha1' }));
```
