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
 * Toggles visibility of collapsible content sections.
 * @param {string} contentId - ID of content div to toggle
 * @param {string} buttonId - ID of toggle button
 */
function toggleShowAll(contentId, buttonId) {
  const content = document.getElementById(contentId);
  const button = document.getElementById(buttonId);
  
  if (content.classList.contains('collapsed')) {
    content.classList.remove('collapsed');
    button.textContent = 'Show Less';
  } else {
    content.classList.add('collapsed');
    button.textContent = 'Show All';
  }
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

  // Check if we need collapsible sections (more than 200 bits ~ 25 bytes)
  const needsCollapse = neededKeyBits > 200;
  const collapsedClass = needsCollapse ? 'class="code-scrollable collapsed"' : 'class="code-scrollable"';

  outEl.innerHTML = `
    <div class="output-section">
      <p><b>Message Statistics:</b></p>
      <p class="small-text">
        • Your message: $${message.length} character(s), $${ptByteLen} byte(s), ${msgBits.length} bits<br>
        • Raw bits sent: ${rawCount} bits<br>
        • After sifting: $${siftedCount} bits (~$${((siftedCount/rawCount)*100).toFixed(1)}% kept)<br>
        • Usable key: ${keyBytesUsable} complete byte(s)
      </p>
    </div>

    <div class="output-section key-cipher-section">
      <p><b>Your Secret Key (send this!):</b> 
        <span class="subtitle-text">Copy and share securely with recipient</span>
        ${needsCollapse ? '<button class="show-all-btn" id="btnToggleKey" onclick="toggleShowAll(\'keyContent\', \'btnToggleKey\')">Show All</button>' : ''}
      </p>
      <div id="keyContent" $${collapsedClass}><code class="code">$${groupedKeyUsed}</code></div>
      <button class="copy-btn" id="copyKeyBtn" onclick="copyToClipboard('${groupedKeyUsed}', 'copyKeyBtn')">Copy Key</button>
      <p><b>Your Ciphertext (send this!):</b>
        <span class="subtitle-text">Encrypted message to share</span>
        ${needsCollapse ? '<button class="show-all-btn" id="btnToggleCipher" onclick="toggleShowAll(\'cipherContent\', \'btnToggleCipher\')">Show All</button>' : ''}
      </p>
      <div id="cipherContent" ${collapsedClass}><code class="code">${groupedCt}</code></div>
      <button class="copy-btn" id="copyCipherBtn" onclick="copyToClipboard('${groupedCt}', 'copyCipherBtn')">Copy Ciphertext</button>
    </div>

    <div class="output-section">
      <p><b>BB84 Protocol Details:</b></p>
      
      <p class="small-text"><b>Alice's bits:</b>
        ${needsCollapse ? '<button class="show-all-btn" id="btnToggleAlice" onclick="toggleShowAll(\'aliceContent\', \'btnToggleAlice\')">Show All</button>' : ''}
      </p>
      <div id="aliceContent" ${collapsedClass}><code class="code">${bitsAStr}</code></div>

      <p class="small-text"><b>Alice's bases:</b>
        ${needsCollapse ? '<button class="show-all-btn" id="btnToggleAliceBases" onclick="toggleShowAll(\'aliceBasesContent\', \'btnToggleAliceBases\')">Show All</button>' : ''}
      </p>
      <div id="aliceBasesContent" ${collapsedClass}><code class="code">${basesAStr}</code></div>

      <p class="small-text"><b>Bob's bases:</b>
        ${needsCollapse ? '<button class="show-all-btn" id="btnToggleBobBases" onclick="toggleShowAll(\'bobBasesContent\', \'btnToggleBobBases\')">Show All</button>' : ''}
      </p>
      <div id="bobBasesContent" ${collapsedClass}><code class="code">${basesBStr}</code></div>

      <p class="small-text"><b>Full sifted key (all ${siftedCount} bits):</b>
        ${needsCollapse ? '<button class="show-all-btn" id="btnToggleSifted" onclick="toggleShowAll(\'siftedContent\', \'btnToggleSifted\')">Show All</button>' : ''}
      </p>
      <div id="siftedContent" ${collapsedClass}><code class="code">${groupedKeyAll}</code></div>

      <p class="small-text"><b>Your plaintext (bits):</b>
        ${needsCollapse ? '<button class="show-all-btn" id="btnTogglePlain" onclick="toggleShowAll(\'plainContent\', \'btnTogglePlain\')">Show All</button>' : ''}
      </p>
      <div id="plainContent" ${collapsedClass}><code class="code">${groupedPt}</code></div>
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
        <p>Key: ${keyBits.length} bits | Ciphertext: ${ctBits.length} bits</p>
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
