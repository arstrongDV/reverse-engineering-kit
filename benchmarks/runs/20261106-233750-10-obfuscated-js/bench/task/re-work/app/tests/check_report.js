const fs=require('fs'),vm=require('vm');
function load(p,exp){const src=fs.readFileSync(p,'utf8')+';\n'+exp;const o={};vm.runInNewContext(src,{console:{log(){}},out:o});return o;}
const a=load('original/app.obfuscated.js','out.f=_0x4c71bc;out.h=_0x3dbba3;');
const b=load('deliverable/app.readable.js','out.f=buildReport;out.h=hashString;');
const cases=[["demo",[{name:"open",time:2},{name:"boot",time:1}]],["x",[]],["é😀",[{name:"😀z",time:5},{name:"a",time:5},{name:"b",time:1}]]];
let ok=true;
cases.forEach((c,i)=>{const same=JSON.stringify(a.f(...c))===JSON.stringify(b.f(...c));console.log((same?'PASS':'FAIL')+' report case '+i);ok&&=same;});
const hs=["","abc","rekit-benchmarkopen","😀"].every(s=>a.h(s)===b.h(s));console.log((hs?'PASS':'FAIL')+' hash');ok&&=hs;
// must-fail case: a different salt must not match
const bad=b.f("demo",[{name:"open",time:1}]).signature!==a.f("demo",[{name:"boot",time:1}]).signature;console.log((bad?'PASS':'FAIL')+' distinguishes different input');
process.exit(ok&&bad?0:1);
