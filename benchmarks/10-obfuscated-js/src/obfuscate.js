const fs = require("fs");
const JavaScriptObfuscator = require("javascript-obfuscator");

const [input, output] = process.argv.slice(2);
const result = JavaScriptObfuscator.obfuscate(fs.readFileSync(input, "utf8"), {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 1,
  identifierNamesGenerator: "hexadecimal",
  renameGlobals: true,
  seed: 20261101,
  simplify: false,
  splitStrings: true,
  splitStringsChunkLength: 6,
  stringArray: true,
  stringArrayEncoding: ["base64"],
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayThreshold: 1,
  transformObjectKeys: true,
});
fs.writeFileSync(output, result.getObfuscatedCode());
