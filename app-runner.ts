import { encryptEnvFile, loadVaultToEnv } from './vaultManager';
import * as path from 'path';

const MASTER_KEY = process.env.MASTER_KEY || 'my-super-secret-master-password-123';
const envFilePath = path.join(__dirname, '.env');
const vaultFilePath = path.join(__dirname, 'secret.vault');

// --- ตัวอย่างที่ 1: ฝั่งผู้ดูแลระบบใช้แปลง .env เป็น .vault (ทำครั้งเดียวหรือเวลาเปลี่ยนค่าลับ) ---
// encryptEnvFile(envFilePath, vaultFilePath, MASTER_KEY);

// --- ตัวอย่างที่ 2: ฝั่งรันไทม์โปรเจกต์ (เรียกใช้ตอนสตาร์ทแอปแทนการอ่าน .env ตรงๆ) ---
try {
  loadVaultToEnv(vaultFilePath, MASTER_KEY);
  
  // ทดสอบเรียกใช้งาน Environment Variable ที่ถูกถอดรหัสเข้ามาสดๆ ใน RAM
  console.log('DATABASE_URL:', process.env.DATABASE_URL);
  console.log('STRIPE_API_KEY:', process.env.STRIPE_API_KEY);

} catch (error) {
  console.error('❌ เกิดข้อผิดพลาดในการโหลด Vault:', (error as Error).message);
}