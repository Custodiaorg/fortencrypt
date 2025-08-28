import { encrypt } from "../src/core/encrypt.mjs";
import { decrypt } from "../src/core/descryprt.mjs";

const data = "Hello World";

const encrypted = encrypt(data);
const decrypted = decrypt(encrypted);

console.log("Encrypted:", encrypted);
console.log("Decrypted:", decrypted);
