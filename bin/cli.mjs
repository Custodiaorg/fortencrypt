#!/usr/bin/env node
import dotenv from "dotenv";
dotenv.config();

import { encrypt, decrypt } from "../src/core/crypto.mjs";

// Ambil argumen CLI
const [,, cmd, payload] = process.argv;

if (!cmd || !payload) {
  console.log("Usage: fortencrypt <encrypt|decrypt> <data|payload>");
  process.exit(1);
}

try {
  if (cmd === "encrypt") {
    const encrypted = encrypt(payload);
    console.log(JSON.stringify(encrypted, null, 2));
  } else if (cmd === "decrypt") {
    const parsed = JSON.parse(payload);
    const decrypted = decrypt(parsed);
    console.log(decrypted.toString());
  } else {
    console.log("Invalid command. Use 'encrypt' or 'decrypt'.");
    process.exit(1);
  }
} catch (err) {
  console.error("Error:", err.message);
  process.exit(1);
}
