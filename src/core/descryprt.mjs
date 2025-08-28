import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();
const MASTER_KEY = Buffer.from(process.env.MASTER_KEY || "", "utf8");

const ALGO = "aes-256-gcm";
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

export function decrypt(encryptedText) {
  if (!MASTER_KEY || MASTER_KEY.length < 32) {
    throw new Error("MASTER_KEY must be at least 32 bytes long");
  }

  const data = Buffer.from(encryptedText, "base64");
  const iv = data.slice(0, IV_LENGTH);
  const tag = data.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = data.slice(IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGO, MASTER_KEY.slice(0, 32), iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
}
