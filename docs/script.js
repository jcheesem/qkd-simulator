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

// Group bit array into 8-bit chunks (drop any leftover bits)
function groupBitsFullBytes(bits) {
    const s = bits.join("");
    const fullLen = (s.length >> 3) << 3; // floor to multiple of 8
    const full = s.slice(0, fullLen);
    return full.replace(/(.{8})/g, "$1 ").trim();
}

// XOR–encrypt and return ASCII-safe hex
function encodeMessageHex(msg, keyBits) {
    // Convert message to bytes (ASCII/UTF-8)
    const msgBytes = new TextEncoder().encode(msg);
    
    // Build key bytes from sifted key bits (only full bytes)
    const keyBytes = [];
    for (let i = 0; i + 7 < keyBits.length; i += 8) {
        keyBytes.push(parseInt(keyBits.slice(i, i + 8).join(""), 2));
    }
    
    // If not enough key bytes, stop
    if (keyBytes.length < msgBytes.length) {
        return "(Error: Sifted key too short to encrypt message!)";
    }
    
    // XOR message bytes with key bytes
    const encryptedBytes = msgBytes.map((b, i) => b ^ keyBytes[i]);
    
    // Return hex and a grouped version (for display)
    const hex = encryptedBytes.map(b => b.toString(16).padStart(2, "0")).join("");
    const groupedHex = hex.replace(/(.{2})/g, "$1 ").trim();
    return { hex, groupedHex, byteLen: encryptedBytes.length };
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
    
    // Increase initial BB84 size so sifted key is long enough
    const MULTIPLIER = 8; // realistic: 8–16
    const n = message.length * 8 * MULTIPLIER;
    
    // Simulate
    const bitsA  = randomBits(n);
    const basesA = randomBases(n);
    const basesB = randomBases(n);
    
    const siftedKey = siftBits(bitsA, basesA, basesB);
    const groupedKey = groupBitsFullBytes(siftedKey);
    
    const enc = encodeMessageHex(message, siftedKey);
    const encryptedHex = enc.hex;
    const encryptedHexGrouped = enc.groupedHex;
    
    const rawCount = n;
    const siftedCount = siftedKey.length;
    const fullKeyBytes = Math.floor(siftedCount / 8);
    
    outEl.innerHTML = `
    <p><b>Raw bits generated:</b> ${rawCount}</p>
    <p><b>Bits kept after sifting:</b> ${siftedCount} (${fullKeyBytes} full bytes usable)</p>
    
    <p><b>Alice bits:</b><br>
       <span class="code">${truncate(bitsA.join(""))}</span></p>
    
    <p><b>Alice bases:</b><br>
       <span class="code">${truncate(basesA.join(""))}</span></p>
    
    <p><b>Bob bases:</b><br>
       <span class="code">${truncate(basesB.join(""))}</span></p>
    
    <p><b>Sifted key (8-bit groups):</b><br>
       <span class="code">${groupedKey}</span></p>
    
    <p><b>Encrypted message (hex):</b> ${enc.byteLen} bytes<br>
       <span class="code">${encryptedHexGrouped}</span></p>
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
