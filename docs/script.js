// ------------------- Utility Functions -------------------

// Generate an array of random bits (0 or 1)
function randomBits(len) {
    return [...crypto.getRandomValues(new Uint8Array(len))].map(b => b % 2);
}

// Generate random bases (+ or ×)
function randomBases(len) {
    return randomBits(len).map(x => x ? "+" : "×");
}

// Keep only positions where Alice and Bob used the same basis
function siftBits(bitsA, basesA, basesB) {
    return bitsA.filter((_, i) => basesA[i] === basesB[i]);
}

// Group bit array into 8-bit chunks
function groupBits(bits) {
    let s = bits.join("");
    return s.replace(/(.{8})/g, "$1 ").trim();
}

// XOR–encrypt a string using repeating bits from the key
function encodeMessage(msg, keyBits) {
    // Convert message into binary (8 bits per character)
    let msgBits = msg.split("").map(ch => {
        return ch.charCodeAt(0).toString(2).padStart(8, "0");
    });

    // Group siftedKey into bytes
    let keyBytes = [];
    for (let i = 0; i + 7 < keyBits.length; i += 8) {
        keyBytes.push(keyBits.slice(i, i + 8).join(""));
    }

    // If not enough key bytes, stop
    if (keyBytes.length < msgBits.length) {
        return "(Error: Sifted key too short to encrypt message!)";
    }

    // XOR msg bytes with key bytes
    let encryptedBits = msgBits.map((byte, i) => {
        let keyByte = keyBytes[i];
        let xor = "";
        for (let j = 0; j < 8; j++) {
            xor += (byte[j] ^ keyByte[j]);
        }
        return xor;
    });

    // Convert encrypted bits → text
    let encryptedChars = encryptedBits.map(b => 
        String.fromCharCode(parseInt(b, 2))
    );

    return encryptedChars.join("");
}
// Truncate each long sequence for display only
function truncate(str, max = 80) {
    return str.length > max ? str.slice(0, max) + "..." : str;
}

// ------------------- Main BB84 Simulation -------------------

function runQKD() {
    let message = document.getElementById("message").value.trim();
    if (message.length === 0) {
        document.getElementById("output").innerHTML =
            "<p>Please enter a message.</p>";
        return;
    }

    // Increase initial BB84 size so sifted key is long enough
    const MULTIPLIER = 8;      // realistic: 8–16
    let n = message.length * 8 * MULTIPLIER;

    let bitsA  = randomBits(n);
    let basesA = randomBases(n);
    let basesB = randomBases(n);
    
    let siftedKey = siftBits(bitsA, basesA, basesB);
    let encrypted = encodeMessage(message, siftedKey);

    // Format 8-bit grouping
    let groupedKey = groupBits(siftedKey);
    
    let rawCount = n;                  // total raw bits generated
    let siftedCount = siftedKey.length; // bits kept after sifting

    document.getElementById("output").innerHTML = `
      <p><b>Raw bits generated:</b> ${rawCount}</p>
      <p><b>Bits kept after sifting:</b> ${siftedCount}</p>
    
      <p><b>Alice bits:</b><br>
         <span class="code">${truncate(bitsA.join(""))}</span></p>
    
      <p><b>Alice bases:</b><br>
         <span class="code">${truncate(basesA.join(""))}</span></p>
    
      <p><b>Bob bases:</b><br>
         <span class="code">${truncate(basesB.join(""))}</span></p>
    
      <p><b>Sifted key (8-bit groups):</b><br>
         <span class="code">${groupedKey}</span></p>
    
      <p><b>Encrypted message:</b><br>
         <span class="code">${encrypted}</span></p>
`;

}
