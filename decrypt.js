async function decryptHtml(password) {
  const enc = window.encryptedData;
  if (!enc) throw new Error('Encrypted data not found');
  const salt = Uint8Array.from(atob(enc.salt), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(enc.iv), c => c.charCodeAt(0));
  const tag = Uint8Array.from(atob(enc.tag), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(enc.data), c => c.charCodeAt(0));

  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), {name: 'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256'},
    keyMaterial,
    {name: 'AES-GCM', length: 256},
    false,
    ['decrypt']
  );
  const cipherBytes = new Uint8Array(data.length + tag.length);
  cipherBytes.set(data);
  cipherBytes.set(tag, data.length);

  const plainBuffer = await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv: iv, tagLength: 128},
    key,
    cipherBytes
  );
  const html = new TextDecoder().decode(plainBuffer);
  document.open();
  document.write(html);
  document.close();
}

window.addEventListener('DOMContentLoaded', () => {
  const pwd = prompt('Enter password to view this page:');
  if (pwd) {
    decryptHtml(pwd).catch(() => alert('Decryption failed.'));
  }
});
