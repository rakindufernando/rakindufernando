const fs = require('fs');
const crypto = require('crypto');

const [,, input, output, password] = process.argv;
if (!input || !output || !password) {
  console.error('Usage: node encrypt.js <input.html> <output.js> <password>');
  process.exit(1);
}

const data = fs.readFileSync(input, 'utf8');
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(data, 'utf8', 'base64');
encrypted += cipher.final('base64');
const tag = cipher.getAuthTag();

const payload = {
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  tag: tag.toString('base64'),
  data: encrypted
};

fs.writeFileSync(output, `window.encryptedData = ${JSON.stringify(payload)};`);
