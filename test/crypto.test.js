import { encrypt, decrypt } from "../src/core/crypto.mjs";

describe("AES-256-GCM", () => {
  test("round-trip string", () => {
    const text = "hello world 🌍";
    const encrypted = encrypt(text);
    const decrypted = decrypt(encrypted).toString();

    expect(decrypted).toBe(text);
  });

  test("round-trip buffer", () => {
    const buf = Buffer.from("secret-buffer-data");
    const encrypted = encrypt(buf);
    const decrypted = decrypt(encrypted);

    expect(decrypted.equals(buf)).toBe(true);
  });
});
