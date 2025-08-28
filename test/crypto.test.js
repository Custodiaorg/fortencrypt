import { encrypt, decrypt } from "../src/core/crypto.mjs";

describe("AES-256-GCM Object Payload", () => {
  test("encrypt & decrypt string correctly", () => {
    const message = "hello world";
    const encrypted = encrypt(message);
    const decrypted = decrypt(encrypted);
    expect(decrypted.toString()).toBe(message);
  });

  test("encrypt & decrypt buffer correctly", () => {
    const message = Buffer.from("buffer test");
    const encrypted = encrypt(message);
    const decrypted = decrypt(encrypted);
    expect(decrypted.equals(message)).toBe(true);
  });

  test("rejects invalid input type", () => {
    expect(() => encrypt(123)).toThrow("Input must be a string or Buffer");
  });

  test("throws error on corrupted payload", () => {
    const corrupted = {
      iv: "00".repeat(12),
      tag: "00".repeat(16),
      ciphertext: "abcd",
    };
    expect(() => decrypt(corrupted)).toThrow(
      "Decryption failed: invalid or corrupted data"
    );
  });
});
