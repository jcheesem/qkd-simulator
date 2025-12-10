// ------------------- Utility Functions -------------------

// Format bits into 8-bit groups with spaces
function formatBitsInGroups(bits) {
  let result = "";
  for (let i = 0; i < bits.length; i++) {
    if (i > 0 && i % 8 === 0) result += " ";
    result += bits[i];
  }
  return result;
}

// XOR two bit arrays
function xorBits(a, b) {
  const len = Math.min(a.length, b.length);
  const result = [];
  for (let i = 0; i < len; i++) {
    result.push(a[i] ^ b[i]);
  }
  return result;
}

// Convert bit array to byte array
function bitsToBytes(bits) {
  const bytes = [];
  for (let i = 0; i + 7 < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | bits[i + j];
    }
    bytes.push(byte);
  }
  return bytes;
}

// Validate binary input (only 0, 1, and spaces)
function validateBinaryInput(str) {
  return /^[01\s]*$/.test(str);
}

// Parse binary string to bit array (ignoring spaces)
function parseBinaryString(str) {
  return str.replace(/\s/g, "").split("").map(ch => parseInt(ch, 10));
}

// Copy to clipboard
function copyToClipboard(text, btnId) {
  const cleanText = text.replace(/\s/g, "");
  navigator.clipboard.writeText(cleanText).then(() => {
    const btn = document.getElementById(btnId);
    const originalText = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = originalText;
    }, 1500);
  }).catch(err => {
    console.error("Failed to copy:", err);
  });
}

// Create truncated display with "Show All" button
function createTruncatedDisplay(str, id, maxChars = 100) {
  if (str.length <= maxChars) {
    return `<span class="code">${str}</span>`;
  }
  
  const truncated = str.substring(0, maxChars);
  return `
    <span class="code" id="${id}-display">${truncated}...</span>
    <button class="show-all-btn" id="${id}-btn" onclick="toggleFullDisplay('${id}', \`${str.replace(/`/g, '\\`')}\`)">Show All</button>
  `;
}

function toggleFullDisplay(id, fullStr) {
  const displayEl = document.getElementById(`${id}-display`);
  const btnEl = document.getElementById(`${id}-btn`);
  
  if (btnEl.textContent === "Show All") {
    displayEl.textContent = fullStr;
    btnEl.textContent = "Show Less";
  } else {
    const truncated = fullStr.substring(0, 100);
    displayEl.textContent = truncated + "...";
    btnEl.textContent = "Show All";
  }
}

// ------------------- BB84 Simulation -------------------

function runQKD() {
  const msgInput = document.getElementById("message");
  const outEl = document.getElementById("output");
  
  if (!msgInput || !outEl) {
    console.error("Required elements not found");
    return;
  }

  const plaintext = msgInput.value;
  if (!plaintext) {
    outEl.innerHTML = "";
    return;
  }

  // Encode plaintext as UTF-8 bytes
  const encoder = new TextEncoder();
  const ptBytes = Array.from(encoder.encode(plaintext));
  const ptByteLen = ptBytes.length;

  // Convert plaintext bytes to bits
  const ptBits = [];
  for (const byte of ptBytes) {
    for (let i = 7; i >= 0; i--) {
      ptBits.push((byte >> i) & 1);
    }
  }
  const neededKeyBits = ptBits.length;

  // Generate more raw bits than needed (accounting for ~50% sifting efficiency)
  const rawCount = Math.max(neededKeyBits * 4, 2000);
  
  // Alice generates random bits and bases
  const bitsA = [];
  const basesA = [];
  for (let i = 0; i < rawCount; i++) {
    bitsA.push(Math.random() < 0.5 ? 0 : 1);
    basesA.push(Math.random() < 0.5 ? 0 : 1);
  }

  // Bob chooses random bases
  const basesB = [];
  for (let i = 0; i < rawCount; i++) {
    basesB.push(Math.random() < 0.5 ? 0 : 1);
  }

  // Sifting: keep bits where bases match
  const siftedKey = [];
  for (let i = 0; i < rawCount; i++) {
    if (basesA[i] === basesB[i]) {
      siftedKey.push(bitsA[i]);
    }
  }

  const siftedCount = siftedKey.length;
  const keyBytesUsable = Math.floor(siftedCount / 8);

  // Only use complete bytes
  const keyBitsUsable = keyBytesUsable * 8;
  const keyBits = siftedKey.slice(0, keyBitsUsable);

  // Use first neededKeyBits of key for encryption
  const keyBitsForEncrypt = keyBits.slice(0, neededKeyBits);

  // Encrypt: ciphertext = plaintext XOR key
  const ctBits = xorBits(ptBits, keyBitsForEncrypt);

  // Format for display
  const groupedKeyUsed = formatBitsInGroups(keyBitsForEncrypt);
  const groupedCt = formatBitsInGroups(ctBits);
  const groupedKeyAll = formatBitsInGroups(keyBits);
  const groupedPt = formatBitsInGroups(ptBits);
  
  const bitsAStr = formatBitsInGroups(bitsA);
  const basesAStr = formatBitsInGroups(basesA);
  const basesBStr = formatBitsInGroups(basesB);

  // Calculate statistics
  const messageChars = plaintext.length;
  const messageBytes = ptByteLen;
  const messageBits = neededKeyBits;
  const percentKept = ((siftedCount / rawCount) * 100).toFixed(1);

  outEl.innerHTML = `
    <div class="output-section key-cipher-section">
      <p><b>Your Secret Key (send this!):</b><br>
         <span class="subtitle-text">Copy and share with recipient</span></p>
      ${createTruncatedDisplay(groupedKeyUsed, 'key-used', 500)}
      <button class="copy-btn" id="copy-key-btn" onclick="copyToClipboard(\`${groupedKeyUsed}\`, 'copy-key-btn')">Copy Key</button>

      <p><b>Your Ciphertext (send this!):</b><br>
         <span class="subtitle-text">Encrypted message</span></p>
      ${createTruncatedDisplay(groupedCt, 'cipher-text', 500)}
      <button class="copy-btn" id="copy-cipher-btn" onclick="copyToClipboard(\`${groupedCt}\`, 'copy-cipher-btn')">Copy Ciphertext</button>
    </div>

    <div class="output-section">
      <p><b>Message Statistics:</b></p>
      <p class="small-text">• Your message: ${messageChars} character(s), ${messageBytes} byte(s), ${messageBits} bits</p>
      <p class="small-text">• Raw bits sent: ${rawCount} bits</p>
      <p class="small-text">• After sifting: ${siftedCount} bits (~${percentKept}% kept)</p>
      <p class="small-text">• Usable key: ${keyBytesUsable} complete byte(s)</p>
    </div>

    <div class="output-section">
      <p><b>BB84 Protocol Details:</b></p>
      
      <p><b>Alice's bits:</b></p>
      ${createTruncatedDisplay(bitsAStr, 'alice-bits', 100)}

      <p><b>Alice's bases:</b></p>
      ${createTruncatedDisplay(basesAStr, 'alice-bases', 100)}

      <p><b>Bob's bases:</b></p>
      ${createTruncatedDisplay(basesBStr, 'bob-bases', 100)}

      <p><b>Sifted key (all usable bytes):</b></p>
      ${createTruncatedDisplay(groupedKeyAll, 'key-all', 500)}

      <p><b>Plaintext bits:</b></p>
      ${createTruncatedDisplay(groupedPt, 'plaintext-bits', 500)}
    </div>
  `;
}

// ------------------- Decryption (Right Panel) -------------------

function decryptMessage() {
  const ctInput = document.getElementById("ciphertext");
  const keyInput = document.getElementById("keyInput");
  const outEl = document.getElementById("decryptOutput");

  if (!ctInput || !keyInput || !outEl) {
    console.error("Required decrypt elements not found");
    return;
  }

  const ctStr = ctInput.value.trim();
  const keyStr = keyInput.value.trim();

  // Validate inputs
  if (!ctStr || !keyStr) {
    outEl.innerHTML = "";
    return;
  }

  if (!validateBinaryInput(ctStr)) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Ciphertext must contain only 0s, 1s, and spaces.</p>
      </div>
    `;
    return;
  }

  if (!validateBinaryInput(keyStr)) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Key must contain only 0s, 1s, and spaces.</p>
      </div>
    `;
    return;
  }

  // Parse to bit arrays
  const ctBits = parseBinaryString(ctStr);
  const keyBits = parseBinaryString(keyStr);

  // Check lengths match
  if (ctBits.length !== keyBits.length) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Ciphertext and key must have the same length.</p>
        <p>Ciphertext: ${ctBits.length} bits, Key: ${keyBits.length} bits</p>
      </div>
    `;
    return;
  }

  // Check length is a multiple of 8
  if (ctBits.length % 8 !== 0) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Bit length must be a multiple of 8.</p>
        <p>Current length: ${ctBits.length} bits</p>
      </div>
    `;
    return;
  }

  // Decrypt: plaintext = ciphertext XOR key
  const ptBits = xorBits(ctBits, keyBits);
  const ptBytes = bitsToBytes(ptBits);

  let decodedMessage;
  try {
    decodedMessage = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(ptBytes));
  } catch (e) {
    decodedMessage = "(Could not decode as UTF-8 text)";
  }

  outEl.innerHTML = `
    <div class="output-section">
      <p><b>Decrypted message:</b></p>
      <p class="code">${decodedMessage}</p>
    </div>
  `;
}

// ------------------- Enter-to-run -------------------
document.addEventListener("DOMContentLoaded", () => {
  const inputEl = document.getElementById("message");
  if (inputEl) {
    inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.code === "NumpadEnter") {
        e.preventDefault();
        runQKD();
      }
    });
  }
});
