import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const rawKey = process.env.MASTER_KEY;
if (!rawKey) {
  throw new Error("MASTER_KEY is missing in environment variables");
}

const MASTER_KEY = Buffer.from(rawKey, "hex");
if (MASTER_KEY.length !== 32) {
  throw new Error("MASTER_KEY must be 32 bytes (64 hex chars) for AES-256-GCM");
}

const ALGO = "aes-256-gcm";
const IV_LENGTH = 12; // recommended for GCM

/**
 * Encrypts data using AES-256-GCM authenticated encryption
 * @param {Buffer|string} input - Data to encrypt (Buffer or UTF-8 string)
 * @returns {{iv: string, tag: string, ciphertext: string}} Encrypted result
 * @throws {Error} If encryption fails
 * @example
 * const encrypted = encrypt("sensitive data");
 * // => { iv: "...", tag: "...", ciphertext: "..." }
 */
export function encrypt(input) {
  try {
    if (!(typeof input === "string" || Buffer.isBuffer(input))) {
      throw new Error("Input must be a string or Buffer");
    }

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGO, MASTER_KEY, iv);

    const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      iv: iv.toString("hex"),
      tag: tag.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
    };
  } catch (err) {
    throw new Error(`Encryption failed: ${err.message}`);
  }
}

/**
 * Decrypts AES-256-GCM encrypted data
 * @param {{iv: string, tag: string, ciphertext: string}} payload - Encrypted payload
 * @returns {Buffer} Decrypted data as Buffer
 * @throws {Error} If decryption fails (invalid key, corrupted data, or auth failure)
 * @example
 * const decrypted = decrypt(encrypted);
 * console.log(decrypted.toString()); // Convert to string
 */
export function decrypt({ iv, tag, ciphertext }) {
  try {
    const decipher = crypto.createDecipheriv(
      ALGO,
      MASTER_KEY,
      Buffer.from(iv, "hex")
    );
    decipher.setAuthTag(Buffer.from(tag, "hex"));

    return Buffer.concat([
      decipher.update(Buffer.from(ciphertext, "hex")),
      decipher.final(),
    ]);
  } catch (err) {
    throw new Error("Decryption failed: invalid or corrupted data");
  }
}
