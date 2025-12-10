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
    if (keyBits.length === 0) return "(No sifted key generated!)";

    return msg
        .split("")
        .map((ch, i) =>
            String.fromCharCode(
                ch.charCodeAt(0) ^ keyBits[i % keyBits.length]
            )
        )
        .join("");
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

    document.getElementById("output").innerHTML = `
      <p><b>Alice bits:</b><br><span class="code">${bitsA.join("")}</span></p>
      <p><b>Alice bases:</b><br><span class="code">${basesA.join("")}</span></p>
      <p><b>Bob bases:</b><br><span class="code">${basesB.join("")}</span></p>

      <p><b>Sifted key (8-bit groups):</b><br>
         <span class="code">${groupedKey}</span></p>

      <p><b>Encrypted message:</b><br>
         <span class="code">${encrypted}</span></p>
    `;
}
