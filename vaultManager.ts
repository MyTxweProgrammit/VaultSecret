import * as crypto from 'crypto';
import * as fs from 'fs';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;     // 256-bit key
const SALT_LENGTH = 16;    // 16 bytes salt
const IV_LENGTH = 12;      // 12 bytes IV (แนะนำสำหรับ GCM)

interface VaultPayload {
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

/**
 * 1. ฟังก์ชันเข้ารหัสไฟล์ .env ปกติ ให้กลายเป็นไฟล์ .vault ปลอดภัย
 */
export function encryptEnvFile(envPath: string, vaultPath: string, masterPassword: string): void {
  if (!fs.existsSync(envPath)) {
    throw new Error(`ไม่พบไฟล์ต้นทางที่: ${envPath}`);
  }

  const envContent = fs.readFileSync(envPath, 'utf8');

  // สุ่ม Salt และ IV ใหม่ทุกครั้งที่เข้ารหัส
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  // แปลง Master Password ให้เป็น Key ความยาว 32 ไบต์ด้วย scrypt
  const key = crypto.scryptSync(masterPassword, salt, KEY_LENGTH);

  // เริ่มกระบวนการเข้ารหัส AES-256-GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let ciphertext = cipher.update(envContent, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');

  const vaultPayload: VaultPayload = {
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag,
    ciphertext: ciphertext
  };

  fs.writeFileSync(vaultPath, JSON.stringify(vaultPayload, null, 2), 'utf8');
  console.log(`🔒 เข้ารหัสสำเร็จ! บันทึกไฟล์ Vault ไว้ที่: ${vaultPath}`);
}

/**
 * 2. ฟังก์ชันถอดรหัสไฟล์ .vault แล้วฉีดค่าลงใน process.env ทันทีตอน Runtime (In-Memory)
 */
export function loadVaultToEnv(vaultPath: string, masterPassword: string): void {
  if (!fs.existsSync(vaultPath)) {
    throw new Error(`ไม่พบไฟล์ Vault ที่: ${vaultPath}`);
  }

  const rawData = fs.readFileSync(vaultPath, 'utf8');
  const payload: VaultPayload = JSON.parse(rawData);

  const salt = Buffer.from(payload.salt, 'hex');
  const iv = Buffer.from(payload.iv, 'hex');
  const tag = Buffer.from(payload.tag, 'hex');
  const ciphertext = payload.ciphertext;

  // Derive Key ด้วยรหัสผ่านเดิมและ Salt ที่เก็บบันทึกไว้
  const key = crypto.scryptSync(masterPassword, salt, KEY_LENGTH);

  // ถอดรหัสและตรวจสอบความถูกต้องของ Auth Tag
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // แยกบรรทัดในเนื้อหา .env แล้ว inject เข้าสู่ process.env ของระบบชั่วคราว
  const lines = decrypted.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue; // ข้ามคอมเมนต์และบรรทัดว่าง

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;

    const keyName = trimmed.substring(0, eqIndex).trim();
    let keyValue = trimmed.substring(eqIndex + 1).trim();

    // จัดการลบ Double/Single Quotes รอบค่าสตริงถ้ามี
    if ((keyValue.startsWith('"') && keyValue.endsWith('"')) ||
        (keyValue.startsWith('\'') && keyValue.endsWith('\''))) {
      keyValue = keyValue.substring(1, keyValue.length - 1);
    }

    process.env[keyName] = keyValue;
  }

  console.log(`🔓 โหลดและถอดรหัส Environment Variables เข้าหน่วยความจำสำเร็จเรียบร้อย!`);
}