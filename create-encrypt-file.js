const fs = require('fs');
const crypto = require('crypto');

// Generate a random 32-byte encryption key
const encryptionKey = crypto.randomBytes(32).toString('hex');

// Create the content for the .env file
const envContent = `ENCRYPTION_KEY=${encryptionKey}\n`;

// Save the generated key to a .env file
fs.writeFileSync('.env', envContent);

console.log('Encryption key saved to .env file!');
