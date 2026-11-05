// Log what goes into and out of crypto calls: keys, IVs, plaintext and digests.
// Dynamic analysis only, inside a VM the user has confirmed. Keys this prints are secrets:
// record where they came from, not their values.
// Run: frida -f ./target -l crypto.js -- <arguments>     (Frida 17)

const MAX_BYTES = 64;

function hex(pointer, length) {
  if (pointer.isNull() || length <= 0) {
    return "";
  }
  const bytes = new Uint8Array(pointer.readByteArray(Math.min(length, MAX_BYTES)));
  const text = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(" ");
  return length > MAX_BYTES ? `${text} ... (${length} bytes)` : text;
}

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

// OpenSSL and BoringSSL. Key and IV lengths depend on the cipher, so the first 32 and 16 bytes
// are shown; the decompiled caller says which cipher it is.
for (const name of ["EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_CipherInit_ex"]) {
  hookExport(name, {
    onEnter(args) {
      console.log(`${name} key=${hex(args[3], 32)} iv=${hex(args[4], 16)}`);
    },
  });
}
hookExport("EVP_EncryptUpdate", {
  onEnter(args) {
    console.log(`EVP_EncryptUpdate in=${hex(args[3], args[4].toInt32())}`);
  },
});
hookExport("EVP_DecryptUpdate", {
  onEnter(args) {
    this.out = args[1];
    this.size = args[2];
  },
  onLeave() {
    console.log(`EVP_DecryptUpdate out=${hex(this.out, this.size.readS32())}`);
  },
});
hookExport("EVP_DigestUpdate", {
  onEnter(args) {
    console.log(`EVP_DigestUpdate data=${hex(args[1], args[2].toInt32())}`);
  },
});

// Apple CommonCrypto: CCCrypt(op, algorithm, options, key, keyLength, iv, in, inLength, ...).
hookExport("CCCrypt", {
  onEnter(args) {
    const operation = args[0].toInt32() === 0 ? "encrypt" : "decrypt";
    const key = hex(args[3], args[4].toInt32());
    console.log(`CCCrypt ${operation} key=${key} iv=${hex(args[5], 16)} in=${hex(args[6], args[7].toInt32())}`);
  },
});

// Windows CNG: BCryptEncrypt(key, input, inputLength, ...) and BCryptDecrypt(...output...).
hookExport("BCryptEncrypt", {
  onEnter(args) {
    console.log(`BCryptEncrypt in=${hex(args[1], args[2].toInt32())}`);
  },
});
hookExport("BCryptDecrypt", {
  onEnter(args) {
    this.out = args[6];
    this.size = args[8];
  },
  onLeave() {
    if (!this.out.isNull()) {
      console.log(`BCryptDecrypt out=${hex(this.out, this.size.readU32())}`);
    }
  },
});

// Java, in Android apps. The frida command line includes the Java bridge.
if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {
    const javaHex = (bytes) => {
      if (bytes === null) {
        return "";
      }
      const shown = [];
      for (let index = 0; index < Math.min(bytes.length, MAX_BYTES); index++) {
        shown.push((bytes[index] & 0xff).toString(16).padStart(2, "0"));
      }
      return bytes.length > MAX_BYTES ? `${shown.join(" ")} ... (${bytes.length} bytes)` : shown.join(" ");
    };
    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algorithm) {
      console.log(`SecretKeySpec ${algorithm} key=${javaHex(key)}`);
      return this.$init(key, algorithm);
    };
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
      const output = this.doFinal(input);
      console.log(`Cipher.doFinal ${this.getAlgorithm()} in=${javaHex(input)} out=${javaHex(output)}`);
      return output;
    };
    const MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overload("[B").implementation = function (input) {
      const output = this.digest(input);
      console.log(`MessageDigest ${this.getAlgorithm()} in=${javaHex(input)} out=${javaHex(output)}`);
      return output;
    };
  });
}
