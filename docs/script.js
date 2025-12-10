/**
 * Converts an array of bytes (0-255) into an array of bits (0s and 1s).
 * Each byte becomes 8 bits, MSB first.
 * @param {Array<number>} bytes - Array of byte values
 * @returns {Array<number>} Array of bits (0 or 1)
 */
function bytesToBits(bytes) {
  const bits = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((b >> i) & 1);
    }
  }
  return bits;
}

/**
 * Converts an array of bits into an array of bytes.
 * Groups bits in chunks of 8, MSB first.
 * @param {Array<number>} bits - Array of bits (0 or 1)
 * @returns {Array<number>} Array of byte values (0-255)
 */
function bitsToBytes(bits) {
  const bytes = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | (bits[i + j] || 0);
    }
    bytes.push(byte);
  }
  return bytes;
}

/**
 * Performs bitwise XOR on two bit arrays.
 * @param {Array<number>} bits1 - First bit array
 * @param {Array<number>} bits2 - Second bit array
 * @returns {Array<number>} XOR result
 */
function xorBits(bits1, bits2) {
  return bits1.map((b, i) => b ^ bits2[i]);
}

/**
 * Formats bit array into groups of 8 with spaces for readability.
 * @param {Array<number>} bits - Array of bits
 * @returns {string} Formatted bit string
 */
function groupBits8(bits) {
  let str = "";
  for (let i = 0; i < bits.length; i++) {
    str += bits[i];
    if ((i + 1) % 8 === 0) str += " ";
  }
  return str.trim();
}

/**
 * Groups bits into complete bytes only (discards incomplete final byte).
 * @param {Array<number>} bits - Array of bits
 * @returns {string} Formatted bit string with complete bytes only
 */
function groupBitsFullBytes(bits) {
  const completeByteCount = Math.floor(bits.length / 8);
  const completeBits = bits.slice(0, completeByteCount * 8);
  return groupBits8(completeBits);
}

/**
 * Validates that a string contains only binary digits and spaces.
 * @param {string} str - Input string to validate
 * @returns {boolean} True if valid binary input
 */
function validateBinaryInput(str) {
  return /^[01\s]+$/.test(str);
}

/**
 * Parses a binary string (with spaces) into an array of bit values.
 * @param {string} str - Binary string (e.g., "01001 10101")
 * @returns {Array<number>} Array of bits (0 or 1)
 */
function parseBinaryString(str) {
  return str.replace(/\s/g, "").split("").map(c => parseInt(c, 10));
}

/**
 * Generates random bits using cryptographically secure randomness.
 * @param {number} len - Number of bits to generate
 * @returns {Array<number>} Array of random bits (0 or 1)
 */
function randomBits(len) {
  return [...crypto.getRandomValues(new Uint8Array(len))].map(b => b % 2);
}

/**
 * Generates random measurement bases for BB84 protocol.
 * Returns "+" for rectilinear or "×" for diagonal basis.
 * @param {number} len - Number of bases to generate
 * @returns {Array<string>} Array of basis symbols ("+" or "×")
 */
function randomBases(len) {
  return randomBits(len).map(x => x ? "+" : "×");
}

/**
 * Sifts bits by keeping only those where Alice and Bob used matching bases.
 * This is the key reconciliation step in BB84 protocol.
 * @param {Array<number>} bitsA - Alice's bits
 * @param {Array<string>} basesA - Alice's measurement bases
 * @param {Array<string>} basesB - Bob's measurement bases
 * @returns {Array<number>} Sifted key (matching bases only)
 */
function siftBits(bitsA, basesA, basesB) {
  return bitsA.filter((_, i) => basesA[i] === basesB[i]);
}

/**
 * Creates a truncated display with "Show All" button for long content.
 * @param {string} content - Full content to display
 * @param {string} id - Unique ID for this display
 * @param {number} maxLines - Maximum lines to show when collapsed (1 or 5-6)
 * @returns {string} HTML string with truncated display
 */
function createTruncatedDisplay(content, id, maxLines = 1) {
  const lineHeight = 20; // approximate pixels per line
  const maxHeight = maxLines * lineHeight;
  
  return `
    <div class="code-container">
      <div id="$${id}" class="code-scrollable collapsed" style="max-height: $${maxHeight}px;">
        ${content}
      </div>
      <button class="show-all-btn" id="btn-$${id}" onclick="toggleShowAll('$${id}', 'btn-${id}')">Show All</button>
    </div>
  `;
}

/**
 * Toggles visibility of collapsible content sections.
 * @param {string} contentId - ID of content div to toggle
 * @param {string} buttonId - ID of toggle button
 */
function toggleShowAll(contentId, buttonId) {
  const content = document.getElementById(contentId);
  const button = document.getElementById(buttonId);
  
  if (content.classList.contains('collapsed')) {
    content.classList.remove('collapsed');
    content.style.maxHeight = 'none';
    button.textContent = 'Show Less';
  } else {
    content.classList.add('collapsed');
    const isOneLine = contentId.includes('alice') || contentId.includes('bob');
    content.style.maxHeight = isOneLine ? '20px' : '120px';
    button.textContent = 'Show All';
  }
}

/**
 * Copies text to clipboard and shows temporary "Copied!" feedback.
 * @param {string} text - Text to copy
 * @param {string} buttonId - ID of button to show feedback on
 */
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

/**
 * Main encryption function - runs BB84 protocol and encrypts user message.
 * Generates random bits/bases, performs key sifting, and encrypts with XOR.
 */
function runQKD() {
  const messageInput = document.getElementById("message");
  const outEl = document.getElementById("output");

  if (!messageInput || !outEl) {
    console.error("Required elements not found");
    return;
  }

  const message = messageInput.value;

  if (!message) {
    outEl.innerHTML = "";
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
        <p>Needed $${neededKeyBits} bits, but only got $${siftedKey.length} bits after sifting.
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
      <p><b>Your Secret Key (send this!):</b><br>
         <span class="subtitle-text">Copy and share with recipient</span></p>
      ${createTruncatedDisplay(groupedKeyUsed, 'key-display', 6)}
      <button class="copy-btn" id="copy-key-btn" onclick="copyToClipboard('${groupedKeyUsed.replace(/'/g, "\\'")}', 'copy-key-btn')">Copy Key</button>

      <p><b>Your Ciphertext (send this!):</b><br>
         <span class="subtitle-text">Encrypted message to share</span></p>
      ${createTruncatedDisplay(groupedCt, 'cipher-display', 6)}
      <button class="copy-btn" id="copy-cipher-btn" onclick="copyToClipboard('${groupedCt.replace(/'/g, "\\'")}', 'copy-cipher-btn')">Copy Ciphertext</button>
    </div>

    <div class="output-section">
      <p><b>Message Statistics:</b></p>
      <p class="small-text">
        • Your message: $${message.length} character(s), $${ptByteLen} byte(s), ${msgBits.length} bits<br>
        • Raw bits sent: ${rawCount} bits<br>
        • After sifting: $${siftedCount} bits (~$${((siftedCount/rawCount)*100).toFixed(1)}% kept)<br>
        • Usable key: ${keyBytesUsable} complete byte(s)
      </p>
    </div>

    <div class="output-section">
      <p><b>BB84 Protocol Details:</b></p>
      
      <p class="small-text"><b>Alice's bits:</b></p>
      ${createTruncatedDisplay(bitsAStr, 'alice-bits', 1)}

      <p class="small-text"><b>Alice's bases:</b></p>
      ${createTruncatedDisplay(basesAStr, 'alice-bases', 1)}

      <p class="small-text"><b>Bob's bases:</b></p>
      ${createTruncatedDisplay(basesBStr, 'bob-bases', 1)}

      <p class="small-text"><b>Full sifted key (all ${siftedCount} bits):</b></p>
      ${createTruncatedDisplay(groupedKeyAll, 'sifted-display', 6)}

      <p class="small-text"><b>Your plaintext (bits):</b></p>
      ${createTruncatedDisplay(groupedPt, 'plaintext-display', 6)}
    </div>
  `;
}

/**
 * Decrypts a ciphertext using the provided key (XOR decryption).
 * Validates input and converts binary strings back to UTF-8 text.
 */
function decryptMessage() {
  const keyInput = document.getElementById("keyInput");
  const cipherInput = document.getElementById("ciphertext");
  const outEl = document.getElementById("decryptOutput");

  if (!keyInput || !cipherInput || !outEl) {
    console.error("Required elements not found");
    return;
  }

  const keyStr = keyInput.value.trim();
  const ctStr = cipherInput.value.trim();

  if (!keyStr || !ctStr) {
    outEl.innerHTML = "";
    return;
  }

  // Validate inputs
  if (!validateBinaryInput(keyStr)) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Key contains invalid characters. Use only 0, 1, and spaces.</p>
      </div>
    `;
    return;
  }

  if (!validateBinaryInput(ctStr)) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Ciphertext contains invalid characters. Use only 0, 1, and spaces.</p>
      </div>
    `;
    return;
  }

  // Parse to bit arrays
  const keyBits = parseBinaryString(keyStr);
  const ctBits = parseBinaryString(ctStr);

  // Check lengths match
  if (keyBits.length !== ctBits.length) {
    outEl.innerHTML = `
      <div class="output-section">
        <p><b>Error:</b> Key and ciphertext lengths don't match.</p>
        <p>Key: $${keyBits.length} bits | Ciphertext: $${ctBits.length} bits</p>
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
    decodedMessage = "(Could not decode as UTF-8 text - data may be corrupted)";
  }

  outEl.innerHTML = `
    <div class="output-section">
      <p><b>Decrypted Message:</b></p>
      <div class="decrypted-message">${decodedMessage}</div>
    </div>
    `;
}

/**
 * Event listener for Enter key to trigger encryption
 */
document.addEventListener("DOMContentLoaded", () => {
  const inputEl = document.getElementById("message");
  if (inputEl) {
    inputEl.addEventListener("keydown", (e) => {
      // Ctrl+Enter or Cmd+Enter to encrypt (allow normal Enter for new lines)
      if ((e.ctrlKey || e.metaKey) && (e.key === "Enter" || e.code === "Enter")) {
        e.preventDefault();
        runQKD();
      }
    });
  }
});
