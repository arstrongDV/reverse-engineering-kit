// Log comparisons, the usual place where a program checks an answer, and watch chosen functions.
// Dynamic analysis only, inside a VM the user has confirmed.
// Run: frida -f ./target -l compare.js -- <arguments>     (Frida 17)

// Functions to watch, by symbol in the main program or by offset from its base, such as
// ["check_serial"] or ["0x7e8"]. Each call logs its first arguments and its return value.
const WATCH = [];
const MAX_TEXT = 80;

function hex(pointer, length) {
  const bytes = new Uint8Array(pointer.readByteArray(Math.min(length, MAX_TEXT)));
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(" ");
}

function show(pointer, length, wide) {
  if (pointer.isNull()) {
    return "NULL";
  }
  try {
    if (length !== undefined) {
      return hex(pointer, length);
    }
    // With a size, Frida 17 reads exactly that many bytes, past the end of the string, so read
    // to the terminator and shorten afterwards.
    const text = wide ? pointer.readUtf16String() : pointer.readUtf8String();
    return JSON.stringify(text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}...` : text);
  } catch (error) {
    return `<${pointer}>`;
  }
}

// Hook an export now, or as soon as a library that has it is loaded.
function hookExport(name, callbacks) {
  let done = false;
  const attach = (address) => {
    if (address !== null && !done) {
      done = true;
      Interceptor.attach(address, callbacks);
    }
  };
  attach(Module.findGlobalExportByName(name));
  if (!done) {
    Process.attachModuleObserver({ onAdded: (module) => attach(module.findExportByName(name)) });
  }
}

function logCompare(name, describe) {
  hookExport(name, {
    onEnter(args) {
      this.call = describe(args);
    },
    onLeave(result) {
      console.log(`${name}(${this.call}) = ${result.toInt32()}`);
    },
  });
}

logCompare("strcmp", (a) => `${show(a[0])}, ${show(a[1])}`);
logCompare("strcasecmp", (a) => `${show(a[0])}, ${show(a[1])}`);
logCompare("strncmp", (a) => `${show(a[0])}, ${show(a[1])}, ${a[2].toInt32()}`);
logCompare("memcmp", (a) => {
  const length = a[2].toInt32();
  return `${show(a[0], length)}, ${show(a[1], length)}, ${length}`;
});
logCompare("lstrcmpA", (a) => `${show(a[0])}, ${show(a[1])}`);
logCompare("lstrcmpiA", (a) => `${show(a[0])}, ${show(a[1])}`);
logCompare("lstrcmpW", (a) => `${show(a[0], undefined, true)}, ${show(a[1], undefined, true)}`);
logCompare("wcscmp", (a) => `${show(a[0], undefined, true)}, ${show(a[1], undefined, true)}`);

for (const target of WATCH) {
  const main = Process.mainModule;
  const address = target.startsWith("0x") ? main.base.add(ptr(target)) : main.findSymbolByName(target);
  if (address === null) {
    console.log(`not found in ${main.name}: ${target}`);
    continue;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.call = [0, 1, 2].map((index) => `${args[index]} ${show(args[index])}`).join(", ");
    },
    onLeave(result) {
      console.log(`${target}(${this.call}) = ${result}`);
    },
  });
}

// Java string checks, in Android apps. The frida command line includes the Java bridge.
if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {
    const JavaString = Java.use("java.lang.String");
    JavaString.equals.implementation = function (other) {
      const result = this.equals(other);
      if (other !== null && this.length() >= 4 && this.length() <= MAX_TEXT) {
        console.log(`String.equals(${JSON.stringify(this.toString())}, ${JSON.stringify(`${other}`)}) = ${result}`);
      }
      return result;
    };
  });
}
