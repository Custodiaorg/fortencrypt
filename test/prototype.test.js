import { describe, it, expect } from "@jest/globals";
import { encrypt } from "../src/core/encrypt.mjs";
import { decrypt } from "../src/core/descryprt.mjs";

describe("Prototype Encryption/Decryption", () => {
  it("should encrypt and decrypt correctly", () => {
    const text = "Hello World";
    const encrypted = encrypt(text);
    const decrypted = decrypt(encrypted);
    expect(decrypted).toBe(text);
  });
});
