import { encrypt, decrypt } from "./../src/core/crypto.mjs";

const data = "Hello World";

const encrypted = encrypt(data);
const decrypted = decrypt(encrypted);

console.log("Encrypted:", encrypted);
console.log("Decrypted:", decrypted);
