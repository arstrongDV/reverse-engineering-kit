// Deobfuscated from app.obfuscated.js (webcrack + manual renaming).
const TELEMETRY_URL = "https://telemetry.example/collect";
const SIGNATURE_SALT = "rekit-benchmark";

// Rolling polynomial hash of the string's code points, modulo 65521.
function hashString(str) {
  const MODULUS = 65521;
  const MULTIPLIER = 31;
  let hash = 0;
  for (const ch of [...str]) {
    hash = (hash * MULTIPLIER + ch.charCodeAt(0)) % MODULUS;
  }
  return hash;
}

// Hex hash of (salt + name) for each name, joined with "-".
function buildSignature(names) {
  return names.map(name => hashString(SIGNATURE_SALT + name).toString(16)).join("-");
}

// Summarize a user's events, ordered by time. Nothing is actually sent to `target`.
function buildReport(user, events) {
  const sorted = [...events].sort((a, b) => a.time - b.time);
  const names = sorted.map(e => e.name);
  return {
    user,
    count: sorted.length,
    first: sorted.length > 0 ? sorted[0].name : "none",
    signature: buildSignature(names),
    target: TELEMETRY_URL
  };
}

console.log(JSON.stringify(buildReport("demo", [
  { name: "open", time: 2 },
  { name: "boot", time: 1 }
])));
