import * as crypto from 'crypto';
import * as fs from 'fs';
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256-bit key
const SALT_LENGTH = 16; // 16 bytes salt
const IV_LENGTH = 12; // 12 bytes IV (Recommend for GCM)
export function encryptEnvFile(envPath, vaultPath, masterPassword) {
    if (!fs.existsSync(envPath)) {
        throw new Error(`File not found at: ${envPath}`);
    }
    const envContent = fs.readFileSync(envPath, 'utf8');
    const salt = crypto.randomBytes(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = crypto.scryptSync(masterPassword, salt, KEY_LENGTH);
    // Encode AES-256-GCM Processing
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let ciphertext = cipher.update(envContent, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    const vaultPayload = {
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        tag: tag,
        ciphertext: ciphertext
    };
    fs.writeFileSync(vaultPath, JSON.stringify(vaultPayload, null, 2), 'utf8');
    console.log(`🔒 Successful Encrypt! Saved file .vault at: ${vaultPath}`);
}
// Decrypt Function
export function loadVaultToEnv(vaultPath, masterPassword) {
    if (!fs.existsSync(vaultPath)) {
        throw new Error(`File not found at: ${vaultPath}`);
    }
    const rawData = fs.readFileSync(vaultPath, 'utf8');
    const payload = JSON.parse(rawData);
    const salt = Buffer.from(payload.salt, 'hex');
    const iv = Buffer.from(payload.iv, 'hex');
    const tag = Buffer.from(payload.tag, 'hex');
    const ciphertext = payload.ciphertext;
    const key = crypto.scryptSync(masterPassword, salt, KEY_LENGTH);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    const lines = decrypted.split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#'))
            continue;
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex === -1)
            continue;
        const keyName = trimmed.substring(0, eqIndex).trim();
        let keyValue = trimmed.substring(eqIndex + 1).trim();
        // Delete Double/Single Quotes Around The String If It has
        if ((keyValue.startsWith('"') && keyValue.endsWith('"')) ||
            (keyValue.startsWith('\'') && keyValue.endsWith('\''))) {
            keyValue = keyValue.substring(1, keyValue.length - 1);
        }
        process.env[keyName] = keyValue;
    }
    console.log(`🔓 Loaded and Decrypted Environment Variables Successfully!`);
}
