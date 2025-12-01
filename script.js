function randomBits(len){ return [...crypto.getRandomValues(new Uint8Array(len))].map(b=>b%2); }
function randomBases(len){ return randomBits(len).map(x=> x ? "+" : "×"); }

function siftBits(bitsA, basesA, basesB){
    return bitsA.filter((_,i)=>basesA[i]===basesB[i]);
}

function encodeMessage(msg,key){
    return msg.split("")
        .map((c,i)=> String.fromCharCode(c.charCodeAt(0) ^ key[i % key.length]))
        .join("");
}

function runQKD(){
    let message = document.getElementById("message").value;

    let n = message.length * 8;     
    let bitsA  = randomBits(n);
    let basesA = randomBases(n);
    let basesB = randomBases(n);

    let siftedKey = siftBits(bitsA,basesA,basesB);
    let encrypted = encodeMessage(message,siftedKey);

    document.getElementById("output").innerHTML = `
      <p><b>Alice bits:</b> ${bitsA.join("")}</p>
      <p><b>Alice bases:</b> ${basesA.join("")}</p>
      <p><b>Bob bases:</b>   ${basesB.join("")}</p>
      <p><b>Sifted key:</b> ${siftedKey.join("")}</p>
      <p><b>Encrypted message:</b> ${encrypted}</p>
    `;
}
