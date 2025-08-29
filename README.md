# FortEncrypt

FortEncrypt is a comprehensive encryption library and CLI tool for Node.js that provides robust cryptographic operations with an intuitive interface. It supports multiple encryption algorithms, compression, and additional authenticated data (AAD) for enhanced security.

## Features

- Multiple encryption algorithms: AES-256-GCM and ChaCha20-Poly1305
- Configurable encryption settings (algorithm, encoding, compression)
- Additional Authenticated Data (AAD) support
- File and directory encryption/decryption
- Key generation and management
- Interactive command-line interface
- Progress indicators for large operations
- Comprehensive error handling

## Installation

Install the package globally for CLI usage:

```bash
npm install -g fortencrypt
```

Or install locally as a dependency:

```bash
npm install fortencrypt
```

## Quick Start

### Generate an Encryption Key

```bash
fortencrypt generate-key -o master.key
```

### Encrypt a File

```bash
fortencrypt encrypt -i secret.txt -o secret.enc -k master.key
```

### Decrypt a File

```bash
fortencrypt decrypt -i secret.enc -o secret.txt -k master.key
```

## CLI Usage

### Generate Key Command

```bash
fortencrypt generate-key [options]
```

Options:
- `-o, --output <file>`: Output file for the key (default: master.key)
- `-l, --length <length>`: Key length in bytes (default: 32)
- `-f, --force`: Overwrite existing key file

### Encrypt Command

```bash
fortencrypt encrypt [input] [options]
```

Options:
- `-i, --input <file>`: Input file to encrypt
- `-t, --text <text>`: Text to encrypt
- `-o, --output <file>`: Output file for encrypted data
- `-k, --key <key>`: Encryption key (hex, file path, or env:VAR_NAME)
- `-a, --algorithm <algorithm>`: Encryption algorithm (default: aes-256-gcm)
- `-e, --encoding <encoding>`: Output encoding (default: hex)
- `-c, --compress`: Enable compression
- `--aad <data>`: Additional authenticated data
- `--stringify`: Output as JSON string
- `-r, --recursive`: Encrypt directory recursively

### Decrypt Command

```bash
fortencrypt decrypt [input] [options]
```

Options:
- `-i, --input <file>`: Input file to decrypt
- `-t, --text <text>`: Text to decrypt
- `-o, --output <file>`: Output file for decrypted data
- `-k, --key <key>`: Decryption key (hex, file path, or env:VAR_NAME)
- `--aad <data>`: Additional authenticated data
- `--buffer`: Return result as buffer
- `-r, --recursive`: Decrypt directory recursively

### Interactive Mode

```bash
fortencrypt interactive
```

Launches an interactive wizard for encryption and decryption operations.

## Programmatic API

### Basic Usage

```javascript
import CryptoLib from 'fortencrypt';

// Initialize with environment key
const crypto = new CryptoLib();
crypto.initialize();

// Encrypt data
const encrypted = await crypto.encrypt('Sensitive data');
console.log(encrypted);

// Decrypt data
const decrypted = await crypto.decrypt(encrypted);
console.log(decrypted); // 'Sensitive data'
```

### Custom Configuration

```javascript
import CryptoLib from 'fortencrypt';

const crypto = new CryptoLib({
  algorithm: 'chacha20-poly1305',
  outputEncoding: 'base64',
  compression: true,
});

// Initialize with custom key
crypto.initialize('your-32-byte-hex-key-here');

const data = { message: 'Hello, World!', number: 42 };

const encrypted = await crypto.encrypt(data);
const decrypted = await crypto.decrypt(encrypted);

console.log(decrypted); // { message: 'Hello, World!', number: 42 }
```

### Using AAD (Additional Authenticated Data)

```javascript
const crypto = new CryptoLib();
crypto.initialize();

const aad = 'authenticated-data';

const encrypted = await crypto.encrypt('secret message', { aad });
const decrypted = await crypto.decrypt(encrypted, { aad });

console.log(decrypted); // 'secret message'
```

### Key Management

```javascript
import { generateAndSaveKey, CryptoLib } from 'fortencrypt';

// Generate and save a key
const key = await generateAndSaveKey('master.key', 32);
console.log(key.toString('hex'));

// Derive a key from a password
const salt = CryptoLib.generateKey(16);
const derivedKey = CryptoLib.deriveKey('my-password', salt, 100000, 32);
```

## Environment Configuration

Set the master key as an environment variable for automatic initialization:

```bash
export MASTER_KEY=your_32_byte_hex_master_key_here
```

Or create a `.env` file in your project root:

```env
MASTER_KEY=your_32_byte_hex_master_key_here
```

## Examples

### Encrypt a Directory Recursively

```bash
fortencrypt encrypt -i documents/ -o encrypted_documents/ -k master.key -r
```

### Decrypt with AAD

```bash
fortencrypt decrypt -i data.enc -o data.txt -k master.key --aad "auth-data"
```

### Use Environment Key

```bash
export MASTER_KEY=$(cat master.key)
fortencrypt encrypt -i file.txt -o file.enc
```

## API Reference

### CryptoLib Class

#### Constructor

`new CryptoLib(config?: Partial<CryptoConfig>): CryptoLib`

Creates a new CryptoLib instance with optional configuration.

#### Methods

- `initialize(masterKey?: string | Buffer | null, encoding?: BufferEncoding): void`
- `setMasterKey(masterKey: string | Buffer, encoding?: BufferEncoding): void`
- `encrypt(input: any, options?: Partial<CryptoConfig>): Promise<EncryptionResult | string>`
- `decrypt(payload: EncryptionResult | string, options?: Partial<CryptoConfig>): Promise<any>`

#### Static Methods

- `generateKey(length?: number): Buffer`
- `deriveKey(password: string, salt: Buffer, iterations?: number, length?: number): Buffer`

### Helper Functions

- `createCryptoLib(config?: Partial<CryptoConfig>): CryptoLib`
- `generateAndSaveKey(filePath: string, length?: number): Promise<Buffer>`
- `loadConfig(filePath: string): Promise<Record<string, any>>`

## Testing

Run the test suite:

```bash
npm test
```

## Security Considerations

- Always use strong, randomly generated keys
- Protect encryption keys with appropriate access controls
- Regularly rotate encryption keys for sensitive data
- Use Additional Authenticated Data (AAD) when appropriate
- Validate decrypted data before use

## License

[MIT](./LICENSE)