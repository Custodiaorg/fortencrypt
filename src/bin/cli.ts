#!/usr/bin/env node

/**
 * @file FortEncrypt CLI - A comprehensive command-line interface for encryption and decryption operations
 * @description Node.js encryption made effortless — configure once, encrypt everywhere
 * @version 1.0.0
 * @license MIT
 * @author Custodiaorg X wAdlEun2ty
 * @see {@link https://github.com/Custodiaorg/fortencrypt.git|https://www.npmjs.com/package/fortencrypt}
 */

import { Command } from "commander";
import chalk from "chalk";
import figlet from "figlet";
import inquirer from "inquirer";
import fs from "fs/promises";
import path from "path";
import ora from "ora";
import cliProgress from "cli-progress";
import CryptoLib, {
  createCryptoLib,
  generateAndSaveKey,
  loadConfig,
} from "../core/crypto";

// Inisialisasi program
const program = new Command();

// Banner
console.log(
  chalk.blue(
    figlet.textSync("FortEncrypt", {
      font: "Standard",
      horizontalLayout: "default",
      verticalLayout: "default",
    })
  )
);
console.log(
  chalk.gray(
    "Node.js encryption made effortless — configure once, encrypt everywhere.\n"
  )
);

/**
 * Reads file content from the specified path
 * @async
 * @function readFile
 * @param {string} filePath - Path to the file to read
 * @returns {Promise<string>} Content of the file
 * @throws {Error} If the file cannot be read
 * @example
 * const content = await readFile('file.txt');
 */
const readFile = async (filePath: string): Promise<string> => {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch (error: any) {
    throw new Error(`Cannot read file: ${filePath} - ${error.message}`);
  }
};

/**
 * Writes data to a file at the specified path
 * @async
 * @function writeFile
 * @param {string} filePath - Path to the file to write
 * @param {string} data - Data to write to the file
 * @returns {Promise<void>}
 * @throws {Error} If the file cannot be written
 * @example
 * await writeFile('output.txt', 'Hello World');
 */
const writeFile = async (filePath: string, data: string): Promise<void> => {
  try {
    await fs.writeFile(filePath, data, "utf8");
  } catch (error: any) {
    throw new Error(`Cannot write file: ${filePath} - ${error.message}`);
  }
};

/**
 * Checks if a file exists at the specified path
 * @async
 * @function fileExists
 * @param {string} filePath - Path to check
 * @returns {Promise<boolean>} True if the file exists, false otherwise
 * @example
 * const exists = await fileExists('file.txt');
 */
const fileExists = async (filePath: string): Promise<boolean> => {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
};

/**
 * Retrieves an encryption key from various sources (environment variable, file, or direct input)
 * @async
 * @function getKeyFromSource
 * @param {string} keySource - Source of the key (env:VAR_NAME, file path, or direct key)
 * @returns {Promise<Buffer>} Encryption key as a Buffer
 * @throws {Error} If the key cannot be retrieved from the specified source
 * @example
 * const key = await getKeyFromSource('env:MASTER_KEY');
 * const key = await getKeyFromSource('keyfile.key');
 * const key = await getKeyFromSource('a1b2c3d4e5f6...');
 */
const getKeyFromSource = async (keySource: string): Promise<Buffer> => {
  const spinner = ora("Loading encryption key").start();

  try {
    if (keySource.startsWith("env:")) {
      const envVar = keySource.substring(4);
      const key = process.env[envVar];
      if (!key) throw new Error(`Environment variable ${envVar} not found`);
      spinner.succeed("Encryption key loaded from environment variable");
      return Buffer.from(key, "hex");
    } else if (await fileExists(keySource)) {
      const keyContent = await readFile(keySource);
      spinner.succeed("Encryption key loaded from file");
      return Buffer.from(keyContent.trim(), "hex");
    } else {
      // Assume it's a direct key
      spinner.succeed("Encryption key loaded from direct input");
      return Buffer.from(keySource, "hex");
    }
  } catch (error: any) {
    spinner.fail("Failed to load encryption key");
    throw error;
  }
};

/**
 * Encrypts a file with progress indication
 * @async
 * @function encryptFile
 * @param {string} inputPath - Path to the input file
 * @param {string} outputPath - Path to the output file
 * @param {CryptoLib} crypto - Initialized CryptoLib instance
 * @param {Object} options - Encryption options
 * @param {string} [options.aad] - Additional authenticated data
 * @returns {Promise<void>}
 * @throws {Error} If encryption fails
 * @example
 * await encryptFile('input.txt', 'output.enc', cryptoInstance, { aad: 'auth-data' });
 */
const encryptFile = async (
  inputPath: string,
  outputPath: string,
  crypto: CryptoLib,
  options: any
) => {
  const progressBar = new cliProgress.SingleBar({
    format:
      "Encrypting |" +
      chalk.cyan("{bar}") +
      "| {percentage}% | {value}/{total} bytes",
    barCompleteChar: "\u2588",
    barIncompleteChar: "\u2591",
    hideCursor: true,
  });

  try {
    const stats = await fs.stat(inputPath);
    const fileSize = stats.size;

    progressBar.start(fileSize, 0);

    // Read file in chunks for large files
    const chunkSize = 64 * 1024; // 64KB chunks
    const fileHandle = await fs.open(inputPath, "r");
    let position = 0;
    let encryptedData = "";

    while (position < fileSize) {
      const buffer = Buffer.alloc(Math.min(chunkSize, fileSize - position));
      const { bytesRead } = await fileHandle.read(
        buffer,
        0,
        buffer.length,
        position
      );

      const chunkEncrypted = await crypto.encrypt(buffer, options);
      encryptedData +=
        typeof chunkEncrypted === "string"
          ? chunkEncrypted
          : JSON.stringify(chunkEncrypted);

      position += bytesRead;
      progressBar.update(position);
    }

    await fileHandle.close();
    progressBar.stop();

    await writeFile(outputPath, encryptedData);
    console.log(chalk.green(`✓ File encrypted successfully: ${outputPath}`));
  } catch (error: any) {
    progressBar.stop();
    throw error;
  }
};

/**
 * Decrypts a file with progress indication
 * @async
 * @function decryptFile
 * @param {string} inputPath - Path to the input file
 * @param {string} outputPath - Path to the output file
 * @param {CryptoLib} crypto - Initialized CryptoLib instance
 * @param {Object} options - Decryption options
 * @param {string} [options.aad] - Additional authenticated data
 * @param {boolean} [options.returnBuffer] - Whether to return result as Buffer
 * @returns {Promise<void>}
 * @throws {Error} If decryption fails
 * @example
 * await decryptFile('input.enc', 'output.txt', cryptoInstance, { aad: 'auth-data' });
 */
const decryptFile = async (
  inputPath: string,
  outputPath: string,
  crypto: CryptoLib,
  options: any
) => {
  const progressBar = new cliProgress.SingleBar({
    format:
      "Decrypting |" +
      chalk.cyan("{bar}") +
      "| {percentage}% | {value}/{total} bytes",
    barCompleteChar: "\u2588",
    barIncompleteChar: "\u2591",
    hideCursor: true,
  });

  try {
    const encryptedData = await readFile(inputPath);
    let payload: any;

    try {
      payload = JSON.parse(encryptedData);
    } catch {
      payload = encryptedData;
    }

    const decrypted = await crypto.decrypt(payload, options);

    if (typeof decrypted === "string") {
      await writeFile(outputPath, decrypted);
    } else if (Buffer.isBuffer(decrypted)) {
      await fs.writeFile(outputPath, decrypted);
    } else {
      await writeFile(outputPath, JSON.stringify(decrypted, null, 2));
    }

    progressBar.stop();
    console.log(chalk.green(`✓ File decrypted successfully: ${outputPath}`));
  } catch (error: any) {
    progressBar.stop();
    throw error;
  }
};

// Main CLI program
program
  .name("fortencrypt")
  .description(
    "Node.js encryption made effortless — configure once, encrypt everywhere."
  )
  .version("1.0.0");

/**
 * Generate Key Command
 * @command generate-key
 * @description Generates a new encryption key and saves it to a file
 * @option -o, --output <file> Output file for the key (default: "master.key")
 * @option -l, --length <length> Key length in bytes (default: "32")
 * @option -f, --force Overwrite existing key file (default: false)
 * @example
 * fortencrypt generate-key -o mykey.key -l 64
 * fortencrypt generate-key --force
 */
program
  .command("generate-key")
  .description("Generate a new encryption key")
  .option("-o, --output <file>", "Output file for the key", "master.key")
  .option("-l, --length <length>", "Key length in bytes", "32")
  .option("-f, --force", "Overwrite existing key file", false)
  .action(async (options) => {
    const spinner = ora("Generating encryption key").start();

    try {
      const length = parseInt(options.length);
      if (isNaN(length) || length < 16) {
        spinner.fail();
        throw new Error("Key length must be a number and at least 16 bytes");
      }

      // Check if file exists and force option
      if ((await fileExists(options.output)) && !options.force) {
        spinner.fail();
        throw new Error(
          `File ${options.output} already exists. Use -f to overwrite.`
        );
      }

      const key = await generateAndSaveKey(options.output, length);
      spinner.succeed();

      console.log(chalk.green("✓ Encryption key generated successfully"));
      console.log(chalk.blue("Key:"), key.toString("hex"));
      console.log(chalk.blue("Saved to:"), options.output);

      // Show usage examples
      console.log("\n" + chalk.yellow("Usage examples:"));
      console.log(
        `  Encrypt: fortencrypt encrypt -i file.txt -o file.enc -k ${options.output}`
      );
      console.log(
        `  Decrypt: fortencrypt decrypt -i file.enc -o file.txt -k ${options.output}`
      );
    } catch (error: any) {
      spinner.fail();
      console.error(chalk.red("✗ Error:"), error.message);
      process.exit(1);
    }
  });

/**
 * Encrypt Command
 * @command encrypt
 * @description Encrypts data or files using specified algorithm and options
 * @argument [input] Input file or text to encrypt (optional)
 * @option -i, --input <file> Input file to encrypt
 * @option -t, --text <text> Text to encrypt
 * @option -o, --output <file> Output file for encrypted data
 * @option -k, --key <key> Encryption key (hex, file path, or env:VAR_NAME)
 * @option -a, --algorithm <algorithm> Encryption algorithm (default: "aes-256-gcm")
 * @option -e, --encoding <encoding> Output encoding (default: "hex")
 * @option -c, --compress Enable compression (default: false)
 * @option --aad <data> Additional authenticated data
 * @option --stringify Output as JSON string (default: false)
 * @option -r, --recursive Encrypt directory recursively (default: false)
 * @example
 * fortencrypt encrypt -i secret.txt -o secret.enc -k env:MASTER_KEY
 * fortencrypt encrypt -t "Hello World" -k keyfile.key --compress
 * fortencrypt encrypt -i folder -o encrypted_folder -r -k mykey
 */
program
  .command("encrypt")
  .description("Encrypt data or file")
  .argument("[input]", "Input file or text to encrypt (optional)")
  .option("-i, --input <file>", "Input file to encrypt")
  .option("-t, --text <text>", "Text to encrypt")
  .option("-o, --output <file>", "Output file for encrypted data")
  .option(
    "-k, --key <key>",
    "Encryption key (hex, file path, or env:VAR_NAME)",
    process.env.MASTER_KEY || ""
  )
  .option("-a, --algorithm <algorithm>", "Encryption algorithm", "aes-256-gcm")
  .option("-e, --encoding <encoding>", "Output encoding", "hex")
  .option("-c, --compress", "Enable compression", false)
  .option("--aad <data>", "Additional authenticated data")
  .option("--stringify", "Output as JSON string", false)
  .option("-r, --recursive", "Encrypt directory recursively", false)
  .action(async (input, options) => {
    const spinner = ora("Initializing encryption").start();

    try {
      // Get encryption key
      if (!options.key) {
        spinner.fail();
        throw new Error(
          "No encryption key provided. Use -k option or set MASTER_KEY environment variable."
        );
      }

      const key = await getKeyFromSource(options.key);

      // Initialize crypto lib
      const crypto = createCryptoLib({
        algorithm: options.algorithm,
        outputEncoding: options.encoding as BufferEncoding,
        compression: options.compress,
        stringifyResult: options.stringify,
      });
      crypto.initialize(key);

      spinner.succeed("Crypto library initialized");

      // Handle recursive directory encryption
      if (options.recursive && options.input) {
        const inputPath = options.input;
        const outputPath = options.output || inputPath + ".encrypted";

        const stats = await fs.stat(inputPath);
        if (!stats.isDirectory()) {
          throw new Error(
            "Input must be a directory when using recursive mode"
          );
        }

        // Create output directory
        await fs.mkdir(outputPath, { recursive: true });

        // Process all files in directory
        const files = await fs.readdir(inputPath);
        const progressBar = new cliProgress.SingleBar({
          format:
            "Processing files |" +
            chalk.cyan("{bar}") +
            "| {percentage}% | {value}/{total} files",
          barCompleteChar: "\u2588",
          barIncompleteChar: "\u2591",
          hideCursor: true,
        });

        progressBar.start(files.length, 0);

        for (const file of files) {
          const fileInputPath = path.join(inputPath, file);
          const fileOutputPath = path.join(outputPath, file + ".enc");

          const fileStats = await fs.stat(fileInputPath);
          if (fileStats.isFile()) {
            await encryptFile(fileInputPath, fileOutputPath, crypto, {
              aad: options.aad,
            });
          }

          progressBar.increment();
        }

        progressBar.stop();
        console.log(
          chalk.green(`✓ Directory encrypted successfully: ${outputPath}`)
        );
        return;
      }

      // Determine input source
      let inputData: string;
      if (options.text) {
        inputData = options.text;
      } else if (options.input) {
        inputData = await readFile(options.input);
      } else if (input) {
        // Check if input is a file path
        if (await fileExists(input)) {
          inputData = await readFile(input);
        } else {
          // Treat as text
          inputData = input;
        }
      } else {
        // Read from stdin
        inputData = await new Promise((resolve) => {
          let data = "";
          process.stdin.on("data", (chunk) => (data += chunk));
          process.stdin.on("end", () => resolve(data));
        });
      }

      if (!inputData) {
        throw new Error("No input data provided");
      }

      // Encrypt data
      const encryptSpinner = ora("Encrypting data").start();
      const encrypted = await crypto.encrypt(inputData, {
        aad: options.aad,
      });
      encryptSpinner.succeed("Data encrypted");

      // Output result
      const result =
        typeof encrypted === "string" ? encrypted : JSON.stringify(encrypted);

      if (options.output) {
        await writeFile(options.output, result);
        console.log(
          chalk.green(`✓ Encrypted data saved to: ${options.output}`)
        );
      } else {
        console.log(result);
      }
    } catch (error: any) {
      spinner.fail();
      console.error(chalk.red("✗ Error:"), error.message);
      process.exit(1);
    }
  });

/**
 * Decrypt Command
 * @command decrypt
 * @description Decrypts previously encrypted data or files
 * @argument [input] Input file or text to decrypt (optional)
 * @option -i, --input <file> Input file to decrypt
 * @option -t, --text <text> Text to decrypt
 * @option -o, --output <file> Output file for decrypted data
 * @option -k, --key <key> Decryption key (hex, file path, or env:VAR_NAME)
 * @option --aad <data> Additional authenticated data
 * @option --buffer Return result as buffer (default: false)
 * @option -r, --recursive Decrypt directory recursively (default: false)
 * @example
 * fortencrypt decrypt -i secret.enc -o secret.txt -k env:MASTER_KEY
 * fortencrypt decrypt -t "ENCRYPTED_DATA" -k keyfile.key
 * fortencrypt decrypt -i encrypted_folder -o decrypted_folder -r -k mykey
 */
program
  .command("decrypt")
  .description("Decrypt data or file")
  .argument("[input]", "Input file or text to decrypt (optional)")
  .option("-i, --input <file>", "Input file to decrypt")
  .option("-t, --text <text>", "Text to decrypt")
  .option("-o, --output <file>", "Output file for decrypted data")
  .option(
    "-k, --key <key>",
    "Decryption key (hex, file path, or env:VAR_NAME)",
    process.env.MASTER_KEY || ""
  )
  .option("--aad <data>", "Additional authenticated data")
  .option("--buffer", "Return result as buffer", false)
  .option("-r, --recursive", "Decrypt directory recursively", false)
  .action(async (input, options) => {
    const spinner = ora("Initializing decryption").start();

    try {
      // Get decryption key
      if (!options.key) {
        spinner.fail();
        throw new Error(
          "No decryption key provided. Use -k option or set MASTER_KEY environment variable."
        );
      }

      const key = await getKeyFromSource(options.key);

      // Initialize crypto lib
      const crypto = createCryptoLib();
      crypto.initialize(key);
      spinner.succeed("Crypto library initialized");

      // Handle recursive directory decryption
      if (options.recursive && options.input) {
        const inputPath = options.input;
        const outputPath =
          options.output || inputPath.replace(".encrypted", "");

        const stats = await fs.stat(inputPath);
        if (!stats.isDirectory()) {
          throw new Error(
            "Input must be a directory when using recursive mode"
          );
        }

        // Create output directory
        await fs.mkdir(outputPath, { recursive: true });

        // Process all files in directory
        const files = await fs.readdir(inputPath);
        const progressBar = new cliProgress.SingleBar({
          format:
            "Processing files |" +
            chalk.cyan("{bar}") +
            "| {percentage}% | {value}/{total} files",
          barCompleteChar: "\u2588",
          barIncompleteChar: "\u2591",
          hideCursor: true,
        });

        progressBar.start(files.length, 0);

        for (const file of files) {
          if (file.endsWith(".enc")) {
            const fileInputPath = path.join(inputPath, file);
            const fileOutputPath = path.join(
              outputPath,
              file.replace(".enc", "")
            );

            await decryptFile(fileInputPath, fileOutputPath, crypto, {
              aad: options.aad,
              returnBuffer: options.buffer,
            });
          }

          progressBar.increment();
        }

        progressBar.stop();
        console.log(
          chalk.green(`✓ Directory decrypted successfully: ${outputPath}`)
        );
        return;
      }

      // Determine input source
      let inputData: string;
      if (options.text) {
        inputData = options.text;
      } else if (options.input) {
        inputData = await readFile(options.input);
      } else if (input) {
        // Check if input is a file path
        if (await fileExists(input)) {
          inputData = await readFile(input);
        } else {
          // Treat as text
          inputData = input;
        }
      } else {
        // Read from stdin
        inputData = await new Promise((resolve) => {
          let data = "";
          process.stdin.on("data", (chunk) => (data += chunk));
          process.stdin.on("end", () => resolve(data));
        });
      }

      if (!inputData) {
        throw new Error("No input data provided");
      }

      // Parse input (could be JSON string or already parsed)
      let payload: any;
      try {
        payload = JSON.parse(inputData);
      } catch {
        // If it's not JSON, assume it's already in the correct format
        payload = inputData;
      }

      // Decrypt data
      const decryptSpinner = ora("Decrypting data").start();
      const decrypted = await crypto.decrypt(payload, {
        aad: options.aad,
        returnBuffer: options.buffer,
      });
      decryptSpinner.succeed("Data decrypted");

      // Output result
      let result: string;
      if (options.buffer && Buffer.isBuffer(decrypted)) {
        result = decrypted.toString("utf8");
      } else if (typeof decrypted === "object") {
        result = JSON.stringify(decrypted, null, 2);
      } else {
        result = String(decrypted);
      }

      if (options.output) {
        await writeFile(options.output, result);
        console.log(
          chalk.green(`✓ Decrypted data saved to: ${options.output}`)
        );
      } else {
        console.log(result);
      }
    } catch (error: any) {
      spinner.fail();
      console.error(chalk.red("✗ Error:"), error.message);
      process.exit(1);
    }
  });

/**
 * Interactive Mode Command
 * @command interactive
 * @description Launches an interactive wizard for encryption/decryption operations
 * @example
 * fortencrypt interactive
 */
program
  .command("interactive")
  .description("Launch interactive encryption/decryption wizard")
  .action(async () => {
    try {
      console.log(chalk.blue("\n=== FortEncrypt Interactive Mode ===\n"));

      const { action } = await inquirer.prompt([
        {
          type: "list",
          name: "action",
          message: "What do you want to do?",
          choices: [
            { name: "Encrypt file or text", value: "encrypt" },
            { name: "Decrypt file or text", value: "decrypt" },
            { name: "Generate encryption key", value: "generate-key" },
          ],
        },
      ]);

      if (action === "generate-key") {
        const { output, length } = await inquirer.prompt([
          {
            type: "input",
            name: "output",
            message: "Where to save the key?",
            default: "master.key",
          },
          {
            type: "number",
            name: "length",
            message: "Key length (bytes):",
            default: 32,
            validate: (value: any) =>
              value >= 16 || "Key must be at least 16 bytes",
          },
        ]);

        const spinner = ora("Generating key").start();
        const key = await generateAndSaveKey(output, length);
        spinner.succeed();

        console.log(chalk.green(`✓ Key generated and saved to: ${output}`));
        console.log(chalk.blue("Key:"), key.toString("hex"));
        return;
      }

      const { keySource } = await inquirer.prompt([
        {
          type: "input",
          name: "keySource",
          message: "Encryption key (hex, file path, or env:VAR_NAME):",
          validate: (value: any) => !!value || "Key is required",
        },
      ]);

      const { inputType } = await inquirer.prompt([
        {
          type: "list",
          name: "inputType",
          message: "Input type:",
          choices: [
            { name: "Text", value: "text" },
            { name: "File", value: "file" },
          ],
        },
      ]);

      let inputData: string;
      if (inputType === "file") {
        const { inputPath } = await inquirer.prompt([
          {
            type: "input",
            name: "inputPath",
            message: "File path:",
            validate: async (value: any) => {
              if (!value) return "File path is required";
              if (!(await fileExists(value))) return "File does not exist";
              return true;
            },
          },
        ]);
        inputData = await readFile(inputPath);
      } else {
        const { text } = await inquirer.prompt([
          {
            type: "input",
            name: "text",
            message: "Text to process:",
            validate: (value: any) => !!value || "Text is required",
          },
        ]);
        inputData = text;
      }

      const { outputPath } = await inquirer.prompt([
        {
          type: "input",
          name: "outputPath",
          message: "Output file (leave empty for console output):",
        },
      ]);

      // Load key and initialize crypto
      const key = await getKeyFromSource(keySource);
      const crypto = createCryptoLib();
      crypto.initialize(key);

      let result: any;
      if (action === "encrypt") {
        const spinner = ora("Encrypting").start();
        result = await crypto.encrypt(inputData, { stringifyResult: true });
        spinner.succeed("Encryption complete");
      } else {
        const spinner = ora("Decrypting").start();
        try {
          result = await crypto.decrypt(JSON.parse(inputData));
        } catch {
          result = await crypto.decrypt(inputData);
        }

        if (typeof result === "object") {
          result = JSON.stringify(result, null, 2);
        }
        spinner.succeed("Decryption complete");
      }

      if (outputPath) {
        await writeFile(outputPath, String(result));
        console.log(chalk.green(`✓ Result saved to: ${outputPath}`));
      } else {
        console.log("\n" + chalk.blue("Result:"));
        console.log(result);
      }
    } catch (error: any) {
      console.error(chalk.red("✗ Error:"), error.message);
      process.exit(1);
    }
  });

// Parse command line arguments
program.parse(process.argv);

// Show help if no arguments
if (!process.argv.slice(2).length) {
  program.outputHelp();
}