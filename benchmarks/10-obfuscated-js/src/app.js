// Benchmark 10: an ordinary script, which obfuscate.js turns into the target.
// The obfuscator only flattens blocks of five or more statements that declare nothing with const
// or let, so these functions use var.
const ENDPOINT = "https://telemetry.example/collect";
const SALT = "rekit-benchmark";

function score(word) {
  var modulus = 65521;
  var multiplier = 31;
  var total = 0;
  var letters = [...word];
  for (var index = 0; index < letters.length; index++) {
    total = (total * multiplier + letters[index].charCodeAt(0)) % modulus;
  }
  return total;
}

function signature(values) {
  return values.map((value) => score(SALT + value).toString(16)).join("-");
}

function buildReport(user, events) {
  var sorted = [...events].sort((left, right) => left.time - right.time);
  var names = sorted.map((event) => event.name);
  var count = sorted.length;
  var first = count > 0 ? sorted[0].name : "none";
  var signed = signature(names);
  return { user, count, first, signature: signed, target: ENDPOINT };
}

console.log(JSON.stringify(buildReport("demo", [{ name: "open", time: 2 }, { name: "boot", time: 1 }])));
