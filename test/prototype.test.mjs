import { encrypt } from "../src/core/encrypt.mjs";
import { decrypt } from "../src/core/descryprt.mjs";
import assert from "assert";
import { test } from "node:test";

test("should encrypt and decrypt correctly", () => {
  const text = "Hello World";
  const encrypted = encrypt(text);
  const decrypted = decrypt(encrypted);
  assert.strictEqual(decrypted, text);
});
