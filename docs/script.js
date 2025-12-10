// ------------------- Utility Functions -------------------

// Generate an array of random bits (0 or 1)
function randomBits(len) {
  return [...crypto.getRandomValues(new Uint8Array(len))].map(b => b % 2);
}

// Generate random bases (+ or ×)
function randomBases(len) {
  return randomBits(len).map(x => (x ? "+" : "×"));
}

// Keep only positions where Alice and Bob used the same basis
function siftBits(bitsA, basesA, basesB) {
  return bitsA.filter((_, i) => basesA[i] === basesB[i]);
}

// Bytes <-> Bits conversion
function bytesToBits(bytes) {
  const bits = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((b >> i) & 1);
    }
  }
  return bits;
}

function bitsToBytes(bits) {
  const bytes = [];
  const full = bits.length - (bits.length % 8);
  for (let i = 0; i < full; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) {
      v = (v << 1) | bits[i + j];
    }
    bytes.push(v);
  }
  return bytes;
}

// XOR two equal-length bit arrays
function xorBits(a, b) {
  return a.map((bit, i) => bit ^ b[i]);
}

// Group bit array into 8-bit chunks (string of 0/1)
function groupBits8(bits) {
  const s = bits.map(b => (b ? "1" : "0")).join("");
  return s.replace(/(.{8})/g, "$1 ").trim();
}

// Group only full bytes from a bit array (drop leftovers)
function groupBitsFullBytes(bits) {
  const s = bits.map(b => (b ? "1" : "0")).join("");
  const fullLen = (s.length >> 3) << 3;
  return s.slice(0, fullLen).replace(/(.{8})/g, "$1 ").trim();
}

// Truncate long sequences for preview only
function truncate(str, max = 80) {
  return str.length > max ? str.slice(0, max) + "..." : str;
}

// Validate binary input (only 0, 1, and spaces)
function validateBinaryInput(str) {
  return /^[01\s]*$/.test(str);
}

// Parse binary string to bit array (ignoring spaces)
function parseBinaryString(str) {
  return str.replace(/\s/g, "").split("").map(ch => parseInt(ch, 10));
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
    outEl.innerHTML = "<p>Please enter a message.</p>";
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
      <p><b>Error:</b> Sifted key too short to encrypt message.</p>
      <p>Needed ${neededKeyBits} bits, but only got ${siftedKey.length} bits after sifting.
      Try a shorter message or increase the multiplier.</p>
    `;
    return;
  }

  // Use exactly the first neededKeyBits for the OTP
  const keyBitsUsed = siftedKey.slice(0, neededKeyBits);

  // Encrypt: ciphertext = plaintext XOR key (bitwise)
  const ctBits = xorBits(msgBits, keyBitsUsed);

  // Prepare display
  const groupedKeyAll  = groupBitsFullBytes(siftedKey);
  const groupedKeyUsed = groupBits8(keyBitsUsed);
  const groupedPt      = groupBits8(msgBits);
  const groupedCt      = groupBits8(ctBits);

  const rawCount = n;
  const siftedCount = siftedKey.length;
  const keyBytesUsable = Math.floor(siftedCount / 8);
  const ptByteLen = msgBytes.length;

  outEl.innerHTML = `
    <p><b>Raw bits generated:</b> ${rawCount}</p>
    <p><b>Bits kept after sifting:</b> ${siftedCount} (${keyBytesUsable} full bytes usable)</p>

    <p><b>Alice bits:</b><br>
       <span class="code">${truncate(bitsA.join(""))}</span></p>

    <p><b>Alice bases:</b><br>
       <span class="code">${truncate(basesA.join(""))}</span></p>

    <p><b>Bob bases:</b><br>
       <span class="code">${truncate(basesB.join(""))}</span></p>

    <p><b>Sifted key (8-bit groups, full bytes only):</b><br>
       <span class="code">${groupedKeyAll}</span></p>

    <p><b>Key used (first ${ptByteLen} bytes = ${neededKeyBits} bits):</b><br>
       <span class="code">${groupedKeyUsed}</span></p>

    <p><b>Plaintext (bits):</b><br>
       <span class="code">${groupedPt}</span></p>

    <p><b>Ciphertext (bits = plaintext XOR key):</b><br>
       <span class="code">${groupedCt}</span></p>
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
    outEl.innerHTML = "<p>Please enter both ciphertext and key.</p>";
    return;
  }

  if (!validateBinaryInput(ctStr)) {
    outEl.innerHTML = "<p><b>Error:</b> Ciphertext must contain only 0s, 1s, and spaces.</p>";
    return;
  }

  if (!validateBinaryInput(keyStr)) {
    outEl.innerHTML = "<p><b>Error:</b> Key must contain only 0s, 1s, and spaces.</p>";
    return;
  }

  // Parse to bit arrays
  const ctBits = parseBinaryString(ctStr);
  const keyBits = parseBinaryString(keyStr);

  // Check lengths match
  if (ctBits.length !== keyBits.length) {
    outEl.innerHTML = `
      <p><b>Error:</b> Ciphertext and key must have the same length.</p>
      <p>Ciphertext: ${ctBits.length} bits, Key: ${keyBits.length} bits</p>
    `;
    return;
  }

  // Check length is a multiple of 8
  if (ctBits.length % 8 !== 0) {
    outEl.innerHTML = `
      <p><b>Error:</b> Bit length must be a multiple of 8.</p>
      <p>Current length: ${ctBits.length} bits</p>
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
    <p><b>Decrypted message:</b></p>
    <p class="code">${decodedMessage}</p>
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

  // Allow Enter in decrypt textareas to trigger decrypt
  const ctInput = document.getElementById("ciphertext");
  const keyInput = document.getElementById("keyInput");
  
  if (ctInput) {
    ctInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.ctrlKey) {
        e.preventDefault();
        decryptMessage();
      }
    });
  }
  
  if (keyInput) {
    keyInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.ctrlKey) {
        e.preventDefault();
        decryptMessage();
      }
    });
  }
});
