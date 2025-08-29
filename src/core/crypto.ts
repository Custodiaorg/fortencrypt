import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import zlib from "zlib";
import { promisify } from "util";
import dotenv from "dotenv";

dotenv.config();

/**
 * Asynchronous version of zlib.deflate
 * @function
 */
const deflateAsync = promisify(zlib.deflate);

/**
 * Asynchronous version of zlib.inflate
 * @function
 */
const inflateAsync = promisify(zlib.inflate);

/**
 * Asynchronous version of zlib.gzip
 * @function
 */
const gzipAsync = promisify(zlib.gzip);

/**
 * Asynchronous version of zlib.gunzip
 * @function
 */
const gunzipAsync = promisify(zlib.gunzip);

/**
 * Supported cryptographic algorithms and their configuration parameters.
 * @namespace
 * @readonly
 * @property {Object} 'aes-256-gcm' - AES-256-GCM algorithm configuration
 * @property {number} 'aes-256-gcm'.ivLength - Initialization vector length in bytes
 * @property {number} 'aes-256-gcm'.keyLength - Key length in bytes
 * @property {number} 'aes-256-gcm'.tagLength - Authentication tag length in bytes
 * @property {Object} 'chacha20-poly1305' - ChaCha20-Poly1305 algorithm configuration
 * @property {number} 'chacha20-poly1305'.ivLength - Initialization vector length in bytes
 * @property {number} 'chacha20-poly1305'.keyLength - Key length in bytes
 * @property {number} 'chacha20-poly1305'.tagLength - Authentication tag length in bytes
 */
const ALGORITHMS = {
  "aes-256-gcm": { ivLength: 12, keyLength: 32, tagLength: 16 },
  "chacha20-poly1305": { ivLength: 12, keyLength: 32, tagLength: 16 },
};

/**
 * Default configuration parameters for cryptographic operations.
 * @namespace
 * @readonly
 * @property {string} algorithm - Default cryptographic algorithm ('aes-256-gcm')
 * @property {string} outputEncoding - Default encoding for output data ('hex')
 * @property {string} inputEncoding - Default encoding for input data ('utf8')
 * @property {boolean} compression - Default compression setting (false)
 * @property {string} compressionAlgorithm - Default compression algorithm ('gzip')
 * @property {boolean} stringifyResult - Default setting for result stringification (false)
 * @property {string} version - Default version identifier ('1.0')
 */
const DEFAULT_CONFIG = {
  algorithm: "aes-256-gcm",
  outputEncoding: "hex",
  inputEncoding: "utf8",
  compression: false,
  compressionAlgorithm: "gzip",
  stringifyResult: false,
  version: "1.0",
};

/**
 * Configuration parameters for cryptographic algorithms.
 * @interface
 */
interface AlgorithmConfig {
  /** Length of initialization vector in bytes */
  ivLength: number;
  /** Length of encryption key in bytes */
  keyLength: number;
  /** Length of authentication tag in bytes */
  tagLength: number;
}

/**
 * Comprehensive configuration for cryptographic operations.
 * @interface
 * @extends CryptoConfig
 */
interface CryptoConfig {
  /** Cryptographic algorithm to use */
  algorithm: string;
  /** Encoding format for output data */
  outputEncoding: BufferEncoding;
  /** Encoding format for input data */
  inputEncoding: BufferEncoding;
  /** Whether to compress data before encryption */
  compression: boolean;
  /** Compression algorithm to use if compression is enabled */
  compressionAlgorithm: string;
  /** Whether to return result as JSON string */
  stringifyResult: boolean;
  /** Version identifier for cryptographic operations */
  version: string;
  /** Additional authenticated data for encryption (optional) */
  aad?: string;
  /** Whether to return decrypted data as Buffer instead of string (optional) */
  returnBuffer?: boolean;
}

/**
 * Structure of encrypted data output.
 * @interface
 */
interface EncryptionResult {
  /** Version identifier */
  v: string;
  /** Algorithm used for encryption */
  algo: string;
  /** Initialization vector in specified encoding */
  iv: string;
  /** Authentication tag in specified encoding */
  tag: string;
  /** Encrypted data in specified encoding */
  data: string;
  /** Whether the data was compressed before encryption */
  compressed: boolean;
}

/**
 * Comprehensive cryptographic library supporting multiple algorithms, compression,
 * and flexible configuration. Provides encryption and decryption capabilities with
 * additional features like compression and authentication.
 *
 * @class
 * @example
 * // Basic usage
 * const cryptoLib = new CryptoLib();
 * cryptoLib.initialize(); // Uses MASTER_KEY from environment
 *
 * const encrypted = await cryptoLib.encrypt('sensitive data');
 * const decrypted = await cryptoLib.decrypt(encrypted);
 */
class CryptoLib {
  /** Current configuration settings */
  private config: CryptoConfig;
  /** Master encryption key */
  private masterKey: Buffer | null;
  /** Initialization status flag */
  private initialized: boolean;

  /**
   * Creates a new CryptoLib instance with optional configuration.
   * @constructor
   * @param {Partial<CryptoConfig>} [config={}] - Configuration overrides
   * @throws {Error} If the specified algorithm is not supported
   * @example
   * // Create instance with custom algorithm
   * const cryptoLib = new CryptoLib({ algorithm: 'chacha20-poly1305' });
   */
  constructor(config: Partial<CryptoConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config } as CryptoConfig;
    this.masterKey = null;
    this.initialized = false;

    if (!ALGORITHMS[this.config.algorithm as keyof typeof ALGORITHMS]) {
      throw new Error(`Unsupported algorithm: ${this.config.algorithm}`);
    }
  }

  /**
   * Initializes the CryptoLib instance with a master key.
   * If no key is provided, attempts to use MASTER_KEY environment variable.
   *
   * @param {string|Buffer|null} [masterKey=null] - Master encryption key
   * @param {BufferEncoding} [encoding='hex'] - Encoding format if key is provided as string
   * @returns {void}
   * @throws {Error} If no master key is provided and MASTER_KEY environment variable is not set
   * @example
   * // Initialize with key from environment
   * cryptoLib.initialize();
   *
   * // Initialize with explicit key
   * cryptoLib.initialize('my-secret-key-hex-string', 'hex');
   */
  initialize(
    masterKey: string | Buffer | null = null,
    encoding: BufferEncoding = "hex"
  ): void {
    if (masterKey) {
      this.setMasterKey(masterKey, encoding);
    } else {
      const envKey = process.env.MASTER_KEY;
      if (!envKey)
        throw new Error("No master key provided and MASTER_KEY env not set");
      this.setMasterKey(envKey, "hex");
    }
    this.initialized = true;
  }

  /**
   * Sets the master encryption key with validation for correct length.
   *
   * @param {string|Buffer} masterKey - Master encryption key
   * @param {BufferEncoding} [encoding='hex'] - Encoding format if key is provided as string
   * @returns {void}
   * @throws {Error} If the key length doesn't match the algorithm requirements
   * @example
   * // Set key from Buffer
   * const keyBuffer = Buffer.from('my-secret-key', 'hex');
   * cryptoLib.setMasterKey(keyBuffer);
   *
   * // Set key from string
   * cryptoLib.setMasterKey('my-secret-key-hex-string', 'hex');
   */
  setMasterKey(
    masterKey: string | Buffer,
    encoding: BufferEncoding = "hex"
  ): void {
    let keyBuffer: Buffer;
    if (Buffer.isBuffer(masterKey)) keyBuffer = masterKey;
    else keyBuffer = Buffer.from(masterKey, encoding);

    const algConfig = ALGORITHMS[
      this.config.algorithm as keyof typeof ALGORITHMS
    ] as AlgorithmConfig;
    if (keyBuffer.length !== algConfig.keyLength)
      throw new Error(
        `Master key must be ${algConfig.keyLength} bytes for ${this.config.algorithm}`
      );

    this.masterKey = keyBuffer;
  }

  /**
   * Generates a cryptographically secure random key.
   *
   * @static
   * @param {number} [length=32] - Length of the key in bytes
   * @returns {Buffer} Randomly generated key
   * @example
   * // Generate a 32-byte key
   * const key = CryptoLib.generateKey();
   *
   * // Generate a 64-byte key
   * const longKey = CryptoLib.generateKey(64);
   */
  static generateKey(length: number = 32): Buffer {
    return crypto.randomBytes(length);
  }

  /**
   * Derives a cryptographic key from a password using PBKDF2.
   *
   * @static
   * @param {string} password - Password to derive key from
   * @param {Buffer} salt - Cryptographic salt
   * @param {number} [iterations=100000] - Number of PBKDF2 iterations
   * @param {number} [length=32] - Length of the derived key in bytes
   * @returns {Buffer} Derived key
   * @example
   * // Derive key from password
   * const salt = crypto.randomBytes(16);
   * const key = CryptoLib.deriveKey('my-password', salt, 100000, 32);
   */
  static deriveKey(
    password: string,
    salt: Buffer,
    iterations = 100_000,
    length = 32
  ): Buffer {
    return crypto.pbkdf2Sync(password, salt, iterations, length, "sha256");
  }

  /**
   * Compresses data using the specified algorithm.
   *
   * @private
   * @param {Buffer} data - Data to compress
   * @param {string} [algorithm='gzip'] - Compression algorithm ('gzip' or 'deflate')
   * @returns {Promise<Buffer>} Compressed data
   * @example
   * // Compress data using gzip
   * const compressed = await this.compress(dataBuffer, 'gzip');
   */
  private async compress(data: Buffer, algorithm = "gzip"): Promise<Buffer> {
    return algorithm === "deflate"
      ? await deflateAsync(data)
      : await gzipAsync(data);
  }

  /**
   * Decompresses data using the specified algorithm.
   *
   * @private
   * @param {Buffer} data - Compressed data
   * @param {string} [algorithm='gzip'] - Compression algorithm ('gzip' or 'deflate')
   * @returns {Promise<Buffer>} Decompressed data
   * @example
   * // Decompress data using gzip
   * const decompressed = await this.decompress(compressedData, 'gzip');
   */
  private async decompress(data: Buffer, algorithm = "gzip"): Promise<Buffer> {
    return algorithm === "deflate"
      ? await inflateAsync(data)
      : await gunzipAsync(data);
  }

  /**
   * Encrypts data with optional compression and additional authentication data.
   *
   * @param {any} input - Data to encrypt (string, Buffer, or object)
   * @param {Partial<CryptoConfig>} [options={}] - Encryption options
   * @returns {Promise<EncryptionResult|string>} Encrypted data structure or JSON string
   * @throws {Error} If CryptoLib is not initialized or input type is invalid
   * @example
   * // Encrypt a string
   * const result = await cryptoLib.encrypt('secret message');
   *
   * // Encrypt an object with compression
   * const result = await cryptoLib.encrypt(
   *   { sensitive: 'data' },
   *   { compression: true }
   * );
   *
   * // Encrypt and get as JSON string
   * const resultString = await cryptoLib.encrypt(
   *   'data',
   *   { stringifyResult: true }
   * );
   */
  async encrypt(
    input: any,
    options: Partial<CryptoConfig> = {}
  ): Promise<EncryptionResult | string> {
    if (!this.initialized || !this.masterKey)
      throw new Error("CryptoLib not initialized");

    const opts = { ...this.config, ...options } as CryptoConfig;
    const algConfig = ALGORITHMS[
      opts.algorithm as keyof typeof ALGORITHMS
    ] as AlgorithmConfig;

    let data: Buffer;
    if (typeof input === "object" && !Buffer.isBuffer(input))
      data = Buffer.from(JSON.stringify(input));
    else if (typeof input === "string")
      data = Buffer.from(input, opts.inputEncoding);
    else if (Buffer.isBuffer(input)) data = input;
    else throw new Error("Invalid input type");

    if (opts.compression)
      data = await this.compress(data, opts.compressionAlgorithm);

    const iv = crypto.randomBytes(algConfig.ivLength);
    const cipher = crypto.createCipheriv(opts.algorithm, this.masterKey, iv);

    if (opts.aad) (cipher as any).setAAD(Buffer.from(opts.aad));

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = (cipher as any).getAuthTag();

    const result: EncryptionResult = {
      v: opts.version,
      algo: opts.algorithm,
      iv: iv.toString(opts.outputEncoding),
      tag: tag.toString(opts.outputEncoding),
      data: encrypted.toString(opts.outputEncoding),
      compressed: opts.compression,
    };

    return opts.stringifyResult ? JSON.stringify(result) : result;
  }

  /**
   * Decrypts previously encrypted data with authentication validation.
   *
   * @param {EncryptionResult|string} payload - Encrypted data structure or JSON string
   * @param {Partial<CryptoConfig>} [options={}] - Decryption options
   * @returns {Promise<any>} Decrypted data (type depends on original input and options)
   * @throws {Error} If CryptoLib is not initialized, payload is invalid, or authentication fails
   * @example
   * // Decrypt previously encrypted data
   * const decrypted = await cryptoLib.decrypt(encryptedResult);
   *
   * // Decrypt from JSON string
   * const decrypted = await cryptoLib.decrypt(encryptedString);
   *
   * // Decrypt with returnBuffer option
   * const decryptedBuffer = await cryptoLib.decrypt(
   *   encryptedResult,
   *   { returnBuffer: true }
   * );
   */
  async decrypt(
    payload: EncryptionResult | string,
    options: Partial<CryptoConfig> = {}
  ): Promise<any> {
    if (!this.initialized || !this.masterKey)
      throw new Error("CryptoLib not initialized");

    const opts = { ...this.config, ...options } as CryptoConfig;
    const payloadObj: EncryptionResult =
      typeof payload === "string" ? JSON.parse(payload) : payload;

    if (!payloadObj.iv || !payloadObj.tag || !payloadObj.data)
      throw new Error("Invalid payload");

    const algorithm = payloadObj.algo || opts.algorithm;
    const algConfig = ALGORITHMS[
      algorithm as keyof typeof ALGORITHMS
    ] as AlgorithmConfig;

    const iv = Buffer.from(payloadObj.iv, opts.outputEncoding);
    const tag = Buffer.from(payloadObj.tag, opts.outputEncoding);
    const encryptedData = Buffer.from(payloadObj.data, opts.outputEncoding);

    const decipher = crypto.createDecipheriv(algorithm, this.masterKey, iv);
    (decipher as any).setAuthTag(tag);

    // Only use AAD from options, not from payload
    if (opts.aad) (decipher as any).setAAD(Buffer.from(opts.aad));

    let decrypted: Buffer;
    try {
      decrypted = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final(),
      ]);
    } catch (error: any) {
      // Safely extract message from various error types
      const rawMsg =
        error && typeof error === "object" && "message" in error
          ? String(error.message)
          : String(error);

      const low = rawMsg.toLowerCase();

      // Substrings commonly appearing in authentication/decryption failures
      const authIndicators = [
        "auth",
        "authenticate",
        "unable to authenticate",
        "unsupported state",
        "bad decrypt",
        "mac",
        "authentication failed",
      ];

      if (authIndicators.some((s) => low.includes(s))) {
        // Throw message expected by your tests
        throw new Error(
          "Authentication failed - data may have been tampered with"
        );
      }

      // If original error was an Error, rethrow to preserve stack trace
      if (error instanceof Error) throw error;

      // Fallback to a clearer message
      throw new Error(`Decryption failed: ${rawMsg}`);
    }

    if (payloadObj.compressed) {
      const decompressed = await this.decompress(
        decrypted,
        opts.compressionAlgorithm
      );
      decrypted = Buffer.from(decompressed);
    }

    try {
      return JSON.parse(decrypted.toString("utf8"));
    } catch {
      return opts.returnBuffer
        ? decrypted
        : decrypted.toString(opts.inputEncoding);
    }
  }
}

/**
 * Creates and initializes a CryptoLib instance with optional configuration.
 *
 * @function
 * @param {Partial<CryptoConfig>} [config={}] - Configuration options
 * @returns {CryptoLib} Initialized CryptoLib instance
 * @example
 * // Create and initialize a CryptoLib instance
 * const cryptoLib = createCryptoLib();
 *
 * // Create with custom configuration
 * const cryptoLib = createCryptoLib({ algorithm: 'chacha20-poly1305' });
 */
export function createCryptoLib(config: Partial<CryptoConfig> = {}): CryptoLib {
  const instance = new CryptoLib(config);
  instance.initialize();
  return instance;
}

/**
 * Loads configuration from a file (JSON or text).
 *
 * @async
 * @function
 * @param {string} filePath - Path to the configuration file
 * @returns {Promise<Record<string, any>>} Configuration object
 * @throws {Error} If the file format is unsupported
 * @example
 * // Load configuration from JSON file
 * const config = await loadConfig('config.json');
 *
 * // Load master key from text file
 * const config = await loadConfig('key.txt');
 */
export async function loadConfig(
  filePath: string
): Promise<Record<string, any>> {
  const ext = path.extname(filePath).toLowerCase();
  const fileContent = await fs.readFile(filePath, "utf8");

  if (ext === ".json") return JSON.parse(fileContent);
  if (ext === ".txt") return { masterKey: fileContent.trim() };
  throw new Error(`Unsupported file format: ${ext}`);
}

/**
 * Generates a cryptographic key and saves it to a file.
 *
 * @async
 * @function
 * @param {string} filePath - Path to save the key file
 * @param {number} [length=32] - Key length in bytes
 * @returns {Promise<Buffer>} Generated key
 * @example
 * // Generate and save a 32-byte key
 * const key = await generateAndSaveKey('master.key');
 *
 * // Generate and save a 64-byte key
 * const key = await generateAndSaveKey('master.key', 64);
 */
export async function generateAndSaveKey(
  filePath: string,
  length = 32
): Promise<Buffer> {
  const key = CryptoLib.generateKey(length);
  await fs.writeFile(filePath, key.toString("hex"));
  return key;
}

export { EncryptionResult };
export default CryptoLib;
