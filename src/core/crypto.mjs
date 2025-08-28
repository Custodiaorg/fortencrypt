import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY, "hex");
if (MASTER_KEY.length !== 32) {
  throw new Error("MASTER_KEY must be 32 bytes (64 hex chars) for AES-256-GCM");
}

const ALGO = "aes-256-gcm";

/**
 * Encrypts data using AES-256-GCM authenticated encryption
 * @param {Buffer|string} input - Data to encrypt (Buffer or UTF-8 string)
 * @returns {Object} Encrypted result containing:
 * @returns {string} iv - Initialization vector (hex)
 * @returns {string} tag - Authentication tag (hex)
 * @returns {string} ciphertext - Encrypted data (hex)
 * @throws {Error} If encryption fails
 * @example
 * const encrypted = encrypt('sensitive data');
 * // Returns: { iv: '...', tag: '...', ciphertext: '...' }
 */
export function encrypt(input) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, MASTER_KEY, iv);

  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
    ciphertext: ciphertext.toString("hex"),
  };
}

/**
 * Decrypts AES-256-GCM encrypted data
 * @param {Object} payload - Encrypted payload object
 * @param {string} payload.iv - Initialization vector (hex)
 * @param {string} payload.tag - Authentication tag (hex)
 * @param {string} payload.ciphertext - Encrypted data (hex)
 * @returns {Buffer} Decrypted data as Buffer
 * @throws {Error} If decryption fails (invalid key, corrupted data, or authentication failure)
 * @example
 * const decrypted = decrypt(encryptedData);
 * console.log(decrypted.toString()); // Convert to string if needed
 */
export function decrypt({ iv, tag, ciphertext }) {
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
}