import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();
const MASTER_KEY = Buffer.from(process.env.MASTER_KEY || "", "utf8");

// AES-256-GCM params
const ALGO = "aes-256-gcm";
const IV_LENGTH = 16; // 128 bit

export function encrypt(text) {
  if (!MASTER_KEY || MASTER_KEY.length < 32) {
    throw new Error("MASTER_KEY must be at least 32 bytes long");
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGO, MASTER_KEY.slice(0, 32), iv);

  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}
