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

// Bytes <-> Bits
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

// Group bit array into 8-bit chunks (string of 0/1)
function groupBits8(bits) {
    const s = bits.map(b => (b ? "1" : "0")).join("");
    return s.replace(/(.{8})/g, "$1 ").trim();
}

// Group any bit array but drop leftover bits that aren't a full byte
function groupBitsFullBytes(bits) {
    const s = bits.map(b => (b ? "1" : "0")).join("");
    const fullLen = (s.length >> 3) << 3;
    return s.slice(0, fullLen).replace(/(.{8})/g, "$1 ").trim();
}

// XOR two equal-length bit arrays
function xorBits(a, b) {
    return a.map((bit, i) => bit ^ b[i]);
}

// Truncate long sequences for preview only
function truncate(str, max = 80) {
    return str.length > max ? str.slice(0, max) + "..." : str;
}

// ------------------- Main BB84 Simulation -------------------

function runQKD() {
    const messageInput = document.getElementById("message");
    const message = messageInput.value.trim();
    const outEl = document.getElementById("output");
    
    if (message.length === 0) {
    outEl.innerHTML = "<p>Please enter a message.</p>";
    return;
    }
    
    // Convert message to bytes and bits (UTF-8)
    const msgBytes = new TextEncoder().encode(message);
    const msgBits = bytesToBits(msgBytes);
    const neededKeyBits = msgBits.length;     // must match plaintext bit length
    
    // Generate raw BB84 size so sifted key is long enough
    // (we need enough bits after sifting to cover the message bits)
    const MULTIPLIER = 8; // realistic: 8–16
    const n = neededKeyBits * MULTIPLIER;
    
    // Simulate
    const bitsA  = randomBits(n);
    const basesA = randomBases(n);
    const basesB = randomBases(n);
    
    const siftedKey = siftBits(bitsA, basesA, basesB);
    
    if (siftedKey.length < neededKeyBits) {
    outEl.innerHTML =
        <p><b>Error:</b> Sifted key too short to encrypt message.</p>
        <p>Needed ${neededKeyBits} bits, but only got ${siftedKey.length} bits after sifting. Try a shorter message or increase the multiplier.</p>    ;
    return;
    }
    
    // Use exactly the first neededKeyBits for OTP
    const keyBitsUsed = siftedKey.slice(0, neededKeyBits);
    
    // Encrypt: ciphertext = plaintext XOR key (bitwise)
    const ctBits = xorBits(msgBits, keyBitsUsed);
    
    // Decrypt (demonstration): plaintext = ciphertext XOR key
    const ptBitsRecovered = xorBits(ctBits, keyBitsUsed);
    const ptBytesRecovered = bitsToBytes(ptBitsRecovered);
    const decodedMessage = new TextDecoder().decode(Uint8Array.from(ptBytesRecovered));
    
    // Prepare display
    const groupedKeyAll = groupBitsFullBytes(siftedKey);
    const groupedKeyUsed = groupBits8(keyBitsUsed);
    const groupedCt = groupBits8(ctBits);
    
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
    
    <p><b>Ciphertext (bits, 8-bit groups):</b><br>
       <span class="code">${groupedCt}</span></p>
    
    <p><b>Decoded message (from ciphertext XOR key):</b><br>
       <span class="code">${decodedMessage}</span></p>
    `;
}

// Run on Enter key
document.addEventListener("DOMContentLoaded", () => {
    const inputEl = document.getElementById("message");
    if (inputEl) {
        inputEl.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                runQKD();
            }
        });
    }
});
