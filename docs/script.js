// ------------------- Helper Functions -------------------

function randomBits(n) {
  const arr = [];
  for (let i = 0; i < n; i++) {
    arr.push(Math.random() < 0.5 ? 0 : 1);
  }
  return arr;
}

function randomBases(n) {
  const arr = [];
  for (let i = 0; i < n; i++) {
    arr.push(Math.random() < 0.5 ? '+' : 'x');
  }
  return arr;
}

function siftBits(bitsA, basesA, basesB) {
  const sifted = [];
  for (let i = 0; i < bitsA.length; i++) {
    if (basesA[i] === basesB[i]) {
      sifted.push(bitsA[i]);
    }
  }
  return sifted;
}

function bytesToBits(bytes) {
  const bits = [];
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  return bits;
}

function bitsToBytes(bits) {
  const bytes = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | bits[i + j];
    }
    bytes.push(byte);
  }
  return bytes;
}

function xorBits(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] ^ b[i]);
  }
  return result;
}

function groupBits8(bits) {
  let str = "";
  for (let i = 0; i < bits.length; i++) {
    if (i > 0 && i % 8 === 0) str += " ";
    str += bits[i];
  }
  return str;
}

function groupBitsFullBytes(bits) {
  const fullByteCount = Math.floor(bits.length / 8);
  const usableBits = bits.slice(0, fullByteCount * 8);
  return groupBits8(usableBits);
}

// Validate binary input (only 0, 1, and spaces)
function validateBinaryInput(str) {
  return /^[01\s]*$/.test(str);
}

// Parse binary string to bit array (ignoring spaces)
function parseBinaryString(str) {
  return str.replace(/\s/g, "").split("").map(ch => parseInt(ch, 10));
}

// Create truncated display with "Show All" button
function createTruncatedDisplay(str, id) {
  const MAX_CHARS = 100;
  if (str.length <= MAX_CHARS) {
    return `<span class="code">${str}</span>`;
  }
  
  const truncated = str.substring(0, MAX_CHARS);
  return `
    <div class="code-container">
      <span class="code" id="${id}-display">${truncated}...</span>
      <button class="show-all-btn" onclick="toggleFullDisplay('${id}', '${str}')">Show All</button>
    </div>
  `;
}

function toggleFullDisplay(id, fullStr) {
  const displayEl = document.getElementById(`${id}-display`);
  const btnEl = event.target;
  
  if (btnEl.textContent === "Show All") {
    displayEl.innerHTML = `<div class="code-scrollable">${fullStr}</div>`;
    btnEl.textContent = "Show Less";
  } else {
    const truncated = fullStr.substring(0, 100);
    displayEl.textContent = truncated + "...";
    btnEl.textContent = "Show All";
  }
}

// Copy to clipboard function
function copyToClipboard(text, buttonId) {
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(buttonId);
    const originalText = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = originalText;
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy:', err);
  });
}

// ------------------- Encryption (Left Panel) -------------------

function runQKD() {
  const messageInput = document.getElementById("message");
  const outEl = document.getElementById("output");

  if (!messageInput || !outEl) {
    console.error("Required elements not found");
    return;
  }

  const message = messageInput.value.trim();

  if (!message) {
    outEl.innerHTML = "";  // Clear output instead of showing empty box
    return;
  }

  // Convert message to bytes and bits (UTF-8)
  const msgBytes = new TextEncoder().encode(message);
  const msgBits = bytesToBits(msgBytes);
  const neededKeyBits = msgBits.length;

  // Generate raw BB84 size so sifted key is long enough
  const MULTIPLIER = 8;
  const n = neededKeyBits * MULTIPLIER;

  // Simulate BB84
  const bitsA  = randomBits(n);
  const basesA = randomBases(n);
  const basesB = randomBases(n);

  const siftedKey = siftBits(bitsA, basesA, basesB);

  if (siftedKey.length < neededKeyBits) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Sifted key too short to encrypt message.</p>
        <p>Needed ${neededKeyBits} bits, but only got ${siftedKey.length} bits after sifting.
        Try a shorter message or increase the multiplier.</p>
      </div>
    `;
    return;
  }

  // Use exactly the first neededKeyBits for the OTP
  const keyBitsUsed = siftedKey.slice(0, neededKeyBits);

  // Encrypt: ciphertext = plaintext XOR key (bitwise)
  const ctBits = xorBits(msgBits, keyBitsUsed);

  // Prepare display strings
  const bitsAStr = bitsA.join("");
  const basesAStr = basesA.join("");
  const basesBStr = basesB.join("");
  const groupedKeyAll  = groupBitsFullBytes(siftedKey);
  const groupedKeyUsed = groupBits8(keyBitsUsed);
  const groupedPt      = groupBits8(msgBits);
  const groupedCt      = groupBits8(ctBits);

  const rawCount = n;
  const siftedCount = siftedKey.length;
  const keyBytesUsable = Math.floor(siftedCount / 8);
  const ptByteLen = msgBytes.length;

  outEl.innerHTML = `
    <div class="output-section key-cipher-section">
      <p><b>Key used</b><br>
         <span class="subtitle-text">first ${ptByteLen} bytes = ${neededKeyBits} bits</span></p>
      <span class="code">${groupedKeyUsed}</span>
      <button class="copy-btn" id="copy-key-btn" onclick="copyToClipboard('${groupedKeyUsed}', 'copy-key-btn')">Copy Key</button>

      <p><b>Ciphertext</b><br>
         <span class="subtitle-text">bits = plaintext XOR key</span></p>
      <span class="code">${groupedCt}</span>
      <button class="copy-btn" id="copy-cipher-btn" onclick="copyToClipboard('${groupedCt}', 'copy-cipher-btn')">Copy Ciphertext</button>
    </div>

    <div class="output-section">
      <p class="small-text"><b>Raw bits generated:</b> ${rawCount}</p>
      <p class="small-text"><b>Bits kept after sifting:</b> ${siftedCount} (${keyBytesUsable} full bytes usable)</p>

      <p><b>Alice bits:</b><br>
         ${createTruncatedDisplay(bitsAStr, 'alice-bits')}</p>

      <p><b>Alice bases:</b><br>
         ${createTruncatedDisplay(basesAStr, 'alice-bases')}</p>

      <p><b>Bob bases:</b><br>
         ${createTruncatedDisplay(basesBStr, 'bob-bases')}</p>

      <p><b>Sifted key</b><br>
         <span class="subtitle-text">8-bit groups, full bytes only</span></p>
      <span class="code">${groupedKeyAll}</span>

      <p><b>Plaintext</b><br>
         <span class="subtitle-text">bits</span></p>
      <span class="code">${groupedPt}</span>
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
    outEl.innerHTML = "";  // Clear output instead of showing message
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
