import { Command } from 'commander';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { spawn } from 'child_process';

const program = new Command();
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

interface VaultPayload {
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

// ฟังก์ชันช่วยรับรหัสผ่านแบบซ่อนตัวอักษรจาก Terminal
function promptPassword(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(query, (password) => {
      rl.close();
      resolve(password);
    });
  });
}

// --- 1. ฟังก์ชันเข้ารหัส ---
function encryptEnvFile(envPath: string, vaultPath: string, masterPassword: string): void {
  if (!fs.existsSync(envPath)) {
    console.error(`❌ Error: ไม่พบไฟล์ต้นทางที่ ${envPath}`);
    process.exit(1);
  }

  const envContent = fs.readFileSync(envPath, 'utf8');
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = crypto.scryptSync(masterPassword, salt, KEY_LENGTH);

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

// --- 2. ฟังก์ชันถอดรหัส คืนค่าเป็น Record<string, string> สำหรับนำไปใช้ต่อ ---
function decryptVaultToMemory(vaultPath: string, masterPassword: string): Record<string, string> {
  if (!fs.existsSync(vaultPath)) {
    console.error(`❌ Error: ไม่พบไฟล์ Vault ที่ ${vaultPath}`);
    process.exit(1);
  }

  try {
    const rawData = fs.readFileSync(vaultPath, 'utf8');
    const payload: VaultPayload = JSON.parse(rawData);

    const salt = Buffer.from(payload.salt, 'hex');
    const iv = Buffer.from(payload.iv, 'hex');
    const tag = Buffer.from(payload.tag, 'hex');

    const key = crypto.scryptSync(masterPassword, salt, KEY_LENGTH);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(payload.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    const envVars: Record<string, string> = {};
    const lines = decrypted.split(/\r?\n/);
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const eqIndex = trimmed.indexOf('=');
      if (eqIndex === -1) continue;

      const keyName = trimmed.substring(0, eqIndex).trim();
      let keyValue = trimmed.substring(eqIndex + 1).trim();

      if ((keyValue.startsWith('"') && keyValue.endsWith('"')) ||
          (keyValue.startsWith('\'') && keyValue.endsWith('\''))) {
        keyValue = keyValue.substring(1, keyValue.length - 1);
      }

      envVars[keyName] = keyValue;
    }

    return envVars;
  } catch (error) {
    console.error(`❌ ถอดรหัสล้มเหลว: รหัสผ่านไม่ถูกต้อง หรือไฟล์ถูกแก้ไข`);
    process.exit(1);
  }
}

// --- การตั้งค่า Commander CLI ---
program
  .name('local-vault')
  .description('CLI tool สำหรับจัดการและเข้ารหัสลับไฟล์ Environment แบบ Zero-Trust')
  .version('1.0.0');

// คำสั่ง encrypt
program
  .command('encrypt')
  .description('แปลงไฟล์ .env ปกติ ให้กลายเป็นไฟล์ .vault ที่เข้ารหัสแล้ว')
  .option('-e, --env <path>', 'path ไปยังไฟล์ .env ต้นทาง', '.env')
  .option('-v, --vault <path>', 'path ปลายทางของไฟล์ vault', 'secret.vault')
  .action(async (options) => {
    const password = await promptPassword('🔑 กำหนด Master Password สำหรับเข้ารหัส: ');
    if (!password) {
      console.error('❌ Error: รหัสผ่านห้ามว่างเปล่า');
      process.exit(1);
    }
    encryptEnvFile(path.resolve(options.env), path.resolve(options.vault), password);
  });

// คำสั่ง decrypt (สำหรับตรวจสอบเนื้อหา)
program
  .command('decrypt')
  .description('ถอดรหัสไฟล์ .vault เพื่อตรวจสอบข้อมูลภายใน')
  .option('-v, --vault <path>', 'path ของไฟล์ vault', 'secret.vault')
  .action(async (options) => {
    const password = await promptPassword('🔑 กรอก Master Password เพื่อปลดล็อก: ');
    if (!password) {
      console.error('❌ Error: Please type your password');
      process.exit(1);
    }
    const envs = decryptVaultToMemory(path.resolve(options.vault), password);
    console.log(`🔓 Successful Decrypt! List of Variable:`, Object.keys(envs));
  });

// [NEW] คำสั่ง run: ถอดรหัสลับเข้า RAM แล้วสปอนแอปพลิเคชันขึ้นมาทันที
program
  .command('run')
  .description('ถอดรหัสไฟล์ Vault แล้วรันคำสั่งแอปพลิเคชันของคุณด้วย Environment ชั่วคราว')
  .option('-v, --vault <path>', 'path ของไฟล์ vault', 'secret.vault')
  .argument('<command...>', 'คำสั่งที่จะรัน เช่น "node index.js" หรือ "npm start"')
  .action(async (commandArgs, options) => {
    const password = await promptPassword('🔑 กรอก Master Password เพื่อปลดล็อกและรันระบบ: ');
    if (!password) {
      console.error('❌ Error: กรุณากรอกรหัสผ่าน');
      process.exit(1);
    }

    // 1. ดึงค่า Environment เข้าสู่ Memory เป็น Object
    const decryptedEnvs = decryptVaultToMemory(path.resolve(options.vault), password);

    // 2. แยกคำสั่งและอาร์กิวเมนต์
    const [cmd, ...args] = commandArgs;

    console.log(`🚀 กำลังรันโปรเจกต์ด้วย Injected Secrets... (${cmd} ${args.join(' ')})\n`);

    // 3. สปอนกระบวนการลูกโดยรวม process.env เดิม เข้ากับตัวแปรที่ถอดรหัสลับ
    const child = spawn(cmd, args, {
      stdio: 'inherit', // เพื่อให้ Log ของแอปพ่นออกมาที่หน้าจอ Terminal ของเราโดยตรง
      env: { ...process.env, ...decryptedEnvs }
    });

    child.on('exit', (code) => {
      process.exit(code || 0);
    });
  });

program.parse(process.argv);