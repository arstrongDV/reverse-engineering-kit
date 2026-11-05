// Log where a program connects and what it sends and receives, including TLS plaintext.
// Dynamic analysis only, inside a VM the user has confirmed, with the network the user chose.
// Run: frida -f ./target -l network.js -- <arguments>     (Frida 17)

const MAX_BYTES = 128;

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

// struct sockaddr: the family is 2 for IPv4 everywhere, and 10, 23, 28 or 30 for IPv6.
function address(sockaddr) {
  if (sockaddr.isNull()) {
    return "NULL";
  }
  const family = Process.platform === "darwin" ? sockaddr.add(1).readU8() : sockaddr.readU16();
  const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
  if (family === 2) {
    const ip = Array.from(new Uint8Array(sockaddr.add(4).readByteArray(4))).join(".");
    return `${ip}:${port}`;
  }
  if ([10, 23, 28, 30].includes(family)) {
    return `[${hex(sockaddr.add(8), 16)}]:${port}`;
  }
  return `family ${family}`;
}

hookExport("connect", {
  onEnter(args) {
    console.log(`connect ${address(args[1])}`);
  },
});
for (const name of ["send", "sendto"]) {
  hookExport(name, {
    onEnter(args) {
      console.log(`${name} ${hex(args[1], args[2].toInt32())}`);
    },
  });
}
for (const name of ["recv", "recvfrom"]) {
  hookExport(name, {
    onEnter(args) {
      this.buffer = args[1];
    },
    onLeave(result) {
      console.log(`${name} ${hex(this.buffer, result.toInt32())}`);
    },
  });
}
// TLS plaintext before encryption and after decryption: OpenSSL, BoringSSL, LibreSSL.
hookExport("SSL_write", {
  onEnter(args) {
    console.log(`SSL_write ${hex(args[1], args[2].toInt32())}`);
  },
});
hookExport("SSL_read", {
  onEnter(args) {
    this.buffer = args[1];
  },
  onLeave(result) {
    console.log(`SSL_read ${hex(this.buffer, result.toInt32())}`);
  },
});

// Java, in Android apps. The frida command line includes the Java bridge.
if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {
    const URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
      console.log(`URL.openConnection ${this.toString()}`);
      return this.openConnection();
    };
    try {
      const OkHttpClient = Java.use("okhttp3.OkHttpClient");
      OkHttpClient.newCall.implementation = function (request) {
        console.log(`OkHttp ${request.method()} ${request.url()} headers: ${request.headers()}`);
        return this.newCall(request);
      };
    } catch (error) {
      console.log("OkHttp is not loaded in this app");
    }
  });
}
