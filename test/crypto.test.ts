// test/crypto.test.ts
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import CryptoLib, {
  createCryptoLib,
  generateAndSaveKey,
  loadConfig,
  EncryptionResult,
} from "../src/core/crypto";

// Mock environment variable
process.env.MASTER_KEY = crypto.randomBytes(32).toString("hex");

describe("CryptoLib", () => {
  let cryptoLib: CryptoLib;
  const testData = {
    message: "Hello, World!",
    number: 42,
    array: [1, 2, 3],
    nested: { key: "value" },
  };

  beforeEach(() => {
    cryptoLib = new CryptoLib();
    cryptoLib.initialize();
  });

  describe("Initialization", () => {
    test("default config initializes", () => {
      expect(cryptoLib).toBeInstanceOf(CryptoLib);
    });

    test("custom config initializes", () => {
      const customCrypto = new CryptoLib({
        algorithm: "chacha20-poly1305",
        outputEncoding: "base64",
        compression: true,
      });
      customCrypto.initialize();
      expect(customCrypto).toBeInstanceOf(CryptoLib);
    });

    test("throws on unsupported algorithm", () => {
      expect(() => new CryptoLib({ algorithm: "unsupported" })).toThrow();
    });

    test("initializes with provided master key", () => {
      const key = CryptoLib.generateKey();
      const customCrypto = new CryptoLib();
      customCrypto.initialize(key);
      expect(customCrypto).toBeInstanceOf(CryptoLib);
    });
  });

  describe("Key Management", () => {
    test("generates valid key", () => {
      const key = CryptoLib.generateKey();
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });

    test("derives key from password", () => {
      const salt = crypto.randomBytes(16);
      const key = CryptoLib.deriveKey("password", salt);
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });

    test("sets master key correctly", () => {
      const key = CryptoLib.generateKey();
      cryptoLib.setMasterKey(key);
      expect(cryptoLib).toBeInstanceOf(CryptoLib);
    });

    test("throws error on invalid key length", () => {
      const shortKey = crypto.randomBytes(16);
      expect(() => cryptoLib.setMasterKey(shortKey)).toThrow();
    });
  });

  describe("Encryption/Decryption", () => {
    test("encrypt/decrypt string", async () => {
      const encrypted = await cryptoLib.encrypt(testData.message);
      const decrypted = await cryptoLib.decrypt(encrypted);
      expect(decrypted).toBe(testData.message);
    });

    test("encrypt/decrypt object", async () => {
      const encrypted = await cryptoLib.encrypt(testData);
      const decrypted = await cryptoLib.decrypt(encrypted);
      expect(decrypted).toEqual(testData);
    });

    test("encrypt/decrypt buffer", async () => {
      const buffer = Buffer.from(testData.message, "utf8");
      const encrypted = await cryptoLib.encrypt(buffer);
      const decrypted = await cryptoLib.decrypt(encrypted, {
        returnBuffer: true,
      });
      expect(Buffer.isBuffer(decrypted)).toBe(true);
      expect(decrypted.toString()).toBe(testData.message);
    });

    test("handles compression", async () => {
      const cryptoCompressed = new CryptoLib({ compression: true });
      cryptoCompressed.initialize();
      const encrypted = await cryptoCompressed.encrypt(testData);
      const decrypted = await cryptoCompressed.decrypt(encrypted);
      expect(decrypted).toEqual(testData);
      expect((encrypted as any).compressed).toBe(true);
    });

    test("handles different encodings", async () => {
      const cryptoBase64 = new CryptoLib({ outputEncoding: "base64" });
      cryptoBase64.initialize();
      const encrypted = await cryptoBase64.encrypt(testData.message);
      const decrypted = await cryptoBase64.decrypt(encrypted);
      expect(decrypted).toBe(testData.message);
    });

    test("handles AAD", async () => {
      const aad = "auth-data";
      const encrypted = await cryptoLib.encrypt(testData.message, { aad });
      const decrypted = await cryptoLib.decrypt(encrypted, { aad });
      expect(decrypted).toBe(testData.message);
    });

    test("throws error with wrong AAD", async () => {
      const aad = "auth-data";
      const wrongAad = "wrong";
      const encrypted = await cryptoLib.encrypt(testData.message, { aad });
      await expect(
        cryptoLib.decrypt(encrypted, { aad: wrongAad })
      ).rejects.toThrow("Authentication failed");
    });
    test("stringifyResult option returns string", async () => {
      const encrypted = await cryptoLib.encrypt(testData.message, {
        stringifyResult: true,
      });
      expect(typeof encrypted).toBe("string");
      const parsed = JSON.parse(encrypted as string);
      expect(parsed).toHaveProperty("iv");
      expect(parsed).toHaveProperty("tag");
      expect(parsed).toHaveProperty("data");
    });

    test("detects tampered data", async () => {
      const encrypted = (await cryptoLib.encrypt(testData.message)) as any;
      const tampered = {
        ...encrypted,
        data: encrypted.data.slice(0, -2) + "00",
      };
      await expect(cryptoLib.decrypt(tampered)).rejects.toThrow(
        "Authentication failed - data may have been tampered with"
      );
    });
  });

  describe("Factory Function", () => {
    test("createCryptoLib returns initialized instance", () => {
      const instance = createCryptoLib();
      expect(instance).toBeInstanceOf(CryptoLib);
    });
  });

  describe("File Operations", () => {
    const testDir = path.join(__dirname, "test-temp");
    const keyPath = path.join(testDir, "test-key.txt");
    const configPath = path.join(testDir, "test-config.json");

    beforeAll(async () => {
      await fs.mkdir(testDir, { recursive: true });
    });

    afterAll(async () => {
      await fs.rm(testDir, { recursive: true, force: true });
    });

    test("generate and save key", async () => {
      const key = await generateAndSaveKey(keyPath);
      expect(Buffer.isBuffer(key)).toBe(true);
      const saved = await fs.readFile(keyPath, "utf8");
      expect(saved).toBe(key.toString("hex"));
    });

    test("load config from JSON", async () => {
      const config = {
        masterKey: process.env.MASTER_KEY,
        algorithm: "aes-256-gcm",
      };
      await fs.writeFile(configPath, JSON.stringify(config));
      const loaded = await loadConfig(configPath);
      expect(loaded).toEqual(config);
    });

    test("load config from text", async () => {
      const key = CryptoLib.generateKey().toString("hex");
      await fs.writeFile(keyPath, key);
      const loaded = await loadConfig(keyPath);
      expect(loaded).toEqual({ masterKey: key });
    });

    test("throws error on unsupported config format", async () => {
      const yamlPath = path.join(testDir, "config.yaml");
      await fs.writeFile(yamlPath, "key: value");
      await expect(loadConfig(yamlPath)).rejects.toThrow();
    });
  });

  describe("Error Handling", () => {
    test("throws when not initialized", async () => {
      const uninit = new CryptoLib();
      await expect(uninit.encrypt("test")).rejects.toThrow("not initialized");
    });

    test("throws for invalid payload", async () => {
      const invalidPayload: EncryptionResult = {
        v: "1.0",
        algo: "aes-256-gcm",
        iv: "",
        tag: "",
        data: "",
        compressed: false,
      };
      await expect(cryptoLib.decrypt(invalidPayload)).rejects.toThrow(
        "Invalid payload"
      );
    });

    test("throws for invalid input type", async () => {
      await expect(cryptoLib.encrypt(123 as any)).rejects.toThrow(
        "Invalid input type"
      );
    });
  });
});
