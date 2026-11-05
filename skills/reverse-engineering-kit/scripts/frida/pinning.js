// Show how an Android app pins certificates: which hosts it checks, against which pins, and
// whether each check passes. It changes nothing, so a failing check still fails.
// Only for apps you own or are authorized to test, inside a VM or test device.
// Run: frida -U -f com.example.app -l pinning.js     (Frida 17)

if (typeof Java === "undefined" || !Java.available) {
  console.log("No Java runtime here: these hooks are for Android apps.");
} else {
  Java.perform(() => {
    const watch = (className, methodName, describe) => {
      let target;
      try {
        target = Java.use(className)[methodName];
      } catch (error) {
        console.log(`${className}.${methodName} is not in this app`);
        return;
      }
      for (const overload of target.overloads) {
        overload.implementation = function (...args) {
          const call = `${className}.${methodName}(${describe(args)})`;
          try {
            const result = overload.call(this, ...args);
            console.log(`${call}: passed`);
            return result;
          } catch (error) {
            console.log(`${call}: FAILED with ${error}`);
            throw error;
          }
        };
      }
    };
    // OkHttp pins, set with CertificatePinner.Builder().add(host, pins).
    watch("okhttp3.CertificatePinner", "check", (args) => `${args[0]}`);
    watch("okhttp3.CertificatePinner", "check$okhttp", (args) => `${args[0]}`);
    // Pins from res/xml/network_security_config.xml.
    watch("android.security.net.config.NetworkSecurityTrustManager", "checkPins", () => "chain");
    // The platform's own chain check, which every TLS connection passes through.
    watch("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", (args) => `${args[2] ?? ""}`);
  });
}
