# fortencrypt

Node.js encryption made effortless  configure once, encrypt everywhere.  
A lightweight AES-256-GCM utility for authenticated encryption and decryption.  

---

##  Features
-  AES-256-GCM authenticated encryption
-  Works with both strings and Buffers
-  Easy to use API (`encrypt`, `decrypt`)
-  CLI support (`npx fortencrypt`)
-  Configurable master key via environment variable
-  Built-in Jest test suite

---

##  Installation

```bash
npm install fortencrypt
```

or with yarn:

```bash
yarn add fortencrypt
```

---

##  Setup

Before using, set a master key via environment variable.
Create a `.env` file in your project root:

```env
MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

> `MASTER_KEY` must be a **64-character hex string (32 bytes)**.

---

##  Usage

### As a Library

```js
import { encrypt, decrypt } from "fortencrypt";

const message = "sensitive data";

// Encrypt
const encrypted = encrypt(message);
console.log(encrypted);
/*
{
  iv: "a1b2c3...",
  tag: "d4e5f6...",
  ciphertext: "deadbeef..."
}
*/

// Decrypt
const decrypted = decrypt(encrypted);
console.log(decrypted.toString()); // "sensitive data"
```

Works with Buffers too:

```js
const buf = Buffer.from("buffer test");
const encrypted = encrypt(buf);
const decrypted = decrypt(encrypted);

console.log(decrypted.equals(buf)); // true
```

---

### Via CLI

`fortencrypt` also provides a simple command-line interface.
After installation, run:

```bash
npx fortencrypt encrypt "hello world"
```

Example output:

```json
{
  "iv": "f9a8c4f5e8c3d9...",
  "tag": "17a36bc9f95a2b...",
  "ciphertext": "d8e9c4f1a3..."
}
```

Decrypt with:

```bash
npx fortencrypt decrypt '{"iv":"...","tag":"...","ciphertext":"..."}'
```

---

##  Environment Variables

* **`MASTER_KEY`**  Required.
  Must be a 32-byte key in hex format (64 hex characters).

Example:

```
MASTER_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

---

##  Limitations

* Focused only on AES-256-GCM encryption/decryption.
* Not a full crypto toolkit (hashing, signatures planned for future).
* Requires secure key management outside of this library.
* Same `MASTER_KEY` must be used for both encryption and decryption.

---

##  Testing

```bash
npm test
```

Example output:

```
 PASS  test/crypto.test.js
  AES-256-GCM Object Payload
     encrypt & decrypt string correctly
     encrypt & decrypt buffer correctly
     rejects invalid input type
     throws error on corrupted payload
```

---

##  License

[MIT](LICENSE)  [custodiaorg](https://github.com/Custodiaorg)