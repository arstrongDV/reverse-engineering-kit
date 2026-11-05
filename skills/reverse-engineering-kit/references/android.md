# Android Packages

APK, AAB and XAPK analysis with jadx and apktool: manifest, permissions, entry points, network
and certificate pinning in apps you own.

## When to use this

Use this file when `triage.json` reports the family `android`: types `apk`, `aab`, `xapk`, `aar`
or `dex`. A split set from a device (`base.apk` and `split_config.*.apk`) counts too: put the
APKs in `original/` and decompile `base.apk` first.

| Tool | Use it for |
| --- | --- |
| `scripts/decompile_apk.py` | jadx Java and apktool resources and smali, plus a summary of the manifest |
| `scripts/find_endpoints.py` | URLs, API paths, HTTP calls, auth headers and masked secrets |
| `scripts/run_ghidra.py` | Native libraries from `lib/<abi>/` |
| `scripts/frida/*.js` | Run-time checks on a test device or emulator the user controls |

Some apps keep their logic outside the Java code, and `decompile_apk.py` says so under
`framework`:

| Framework | Where the logic is | Route |
| --- | --- | --- |
| React Native | `assets/index.android.bundle` | [js-electron.md](js-electron.md); Hermes bytecode is not covered yet |
| Flutter | `lib/<abi>/libapp.so`, compiled Dart | Strings and symbols only; Dart decompilation is not covered |
| Cordova or Capacitor | `assets/www/` or `assets/public/` | [js-electron.md](js-electron.md) |
| .NET (Xamarin or MAUI) | `assemblies/` | Not covered in this version |
| Unity IL2CPP | `libil2cpp.so` plus metadata | Not covered in this version |

A phone stores an app from the Play Store as several APKs: `base.apk` plus split APKs for the
screen density, language and processor. The code is almost always in `base.apk`; native
libraries are in the split named for the processor, such as `split_config.arm64_v8a.apk`.

## First 15 minutes

1. Decompile, and read the summary:

```
python scripts/decompile_apk.py
python scripts/find_endpoints.py
```

   Code goes to `decompiled/jadx/sources/`, resources and smali to `decompiled/apktool/`, and
   the summary to `decompiled/android.json`.
2. Note what the manifest exposes: exported components and the permissions guarding them,
   `debuggable`, `allowBackup`, deep links and the network security config.
3. Read the entry points in this order: the `Application` class if one is named, the launcher
   activity, then any exported service, receiver or provider.
4. Read the endpoints list. Paths and URLs from libraries such as `androidx` or `okhttp3` are
   counted separately, because they are rarely the app's own.
5. For every endpoint you want to claim, find the code that builds the request: method, headers
   and body. A literal URL in a call is enough for an API endpoint; anything assembled at run
   time needs reproducing.
6. Native libraries: triage each by path and analyze it with `run_ghidra.py`. Exported functions
   named `Java_<package>_<class>_<method>` are the ones Java calls.

## Signal → next step

| Signal | Next step |
| --- | --- |
| An exported component with no `permission` | Read how it handles its intent; that is the app's attack surface |
| `debuggable` is `true` | A finding in a release build: anyone with the phone can debug it |
| `allowBackup` is `true` | App data can be copied off the device with a backup |
| Cleartext permitted for a domain | A finding: list the domains |
| A `pin-set` in the network security config, or OkHttp `CertificatePinner` | Pinning: see below |
| Trust in user certificates | The app accepts certificates the user installs |
| URLs or keys missing from the strings | Look for an `int[]` or `byte[]` decoded at run time, or a reversed or split string |
| A key or token in the code | Record where it is and what it reaches, never its value |
| Retrofit interfaces (`@GET`, `@POST`) | The full API surface, one method per endpoint |
| Names such as `a.b.c` | ProGuard or R8 renaming: follow strings and Android API calls instead |
| `System.loadLibrary("x")` | `lib<abi>/libx.so` holds code: [native.md](native.md) |

More signals from the code itself:

| Signal | Next step |
| --- | --- |
| `addJavascriptInterface` on a WebView | Java methods callable from web pages; list them and the pages loaded |
| `setJavaScriptEnabled(true)` with `loadUrl` of a non-HTTPS page | A finding: script on that page can be replaced on the network |
| A `PendingIntent` without `FLAG_IMMUTABLE` | Another app may fill in its intent; required since API 31 |
| A content provider building SQL from its arguments | Possible injection through the provider |
| `*.firebaseio.com` or `google_api_key` in resources | Configuration, often meant to be public. Record it; do not query the service |
| Root or emulator checks, such as looking for `su` | [anti-analysis.md](anti-analysis.md) |
| Kotlin `Intrinsics.checkNotNullParameter(x, "name")` | The real parameter name, even in renamed code |

jadx's `--deobf` option renames short names consistently across the app, which helps when every
class is called `a`. It is not on by default, because the new names are invented.

Pinning in an app the user owns: the cleanest way to see its traffic is a debug build whose
network security config trusts a test certificate inside `<debug-overrides>`. To learn how the
release build pins, run `scripts/frida/pinning.js` on a test device: it logs each host checked
and whether the check passed, and changes nothing.

## Common traps

- **jadx and XAPK.** jadx accepts an XAPK file and writes no code. `decompile_apk.py` unpacks the
  APKs and gives them to jadx one by one.
- **apktool and AAB.** apktool does not read App Bundles, so an AAB gets jadx output only.
- **Exported by default.** Before API 31, a component with an intent filter was exported unless
  it said otherwise. `decompile_apk.py` applies the rule for the app's `targetSdkVersion`.
- **Folded constants.** `"/v2/" + "session"` in the source becomes one string in the bytecode, so
  it is found. A string assembled at run time is not, and needs reading.
- **Code jadx could not decompile.** jadx marks such methods with a comment. Read the smali for
  them in `decompiled/apktool/smali/`.
- **Resource IDs.** Numbers such as `0x7f0e0042` are resources. Look them up in
  `decompiled/apktool/res/values/public.xml`.
- **Testing someone else's server.** An endpoint list describes the client. Do not send requests
  to a server the user does not own or may not test.

## Worked example

Benchmark 5 is a small app built for this project, whose answer is its endpoint list and
authentication flow. These are the real outputs, shortened.

```
$ python scripts/decompile_apk.py
fieldnotes.apk: com.fieldnotes.demo 1.2.0
  sdk: {'min': 21, 'target': 23}, application: {'allowBackup': 'false'}
  permissions: android.permission.INTERNET
  components: 1, exported: 1
    activity com.fieldnotes.demo.MainActivity (launcher)

$ python scripts/find_endpoints.py
paths: 2 in the app
  /v2/session  (2x, at decompiled/jadx/sources/com/fieldnotes/demo/Endpoints.java:20)
  /v2/notes/sync  (2x, at decompiled/jadx/sources/com/fieldnotes/demo/Endpoints.java:24)
headers: 2 in the app
  X-App-Key ...
  Authorization ...
```

Two paths and no host. `Endpoints.java` showed why:

```java
    private static final int[] BASE = {95, 67, 67, 71, 68, 13, 24, 24, 86, 71, 94, 25, ...};
    private static final int KEY = 55;
    ...
            sb.append((char) (i ^ KEY));
    ...
    static String diagnostics() {
        return base() + ((Object) new StringBuilder("gaid/lanretni/").reverse());
```

XORing `BASE` with 55 in Python gave `https://api.fieldnotes.example`, and reversing the string
gave a third path, `/internal/diag`. `MainActivity` calls it only when the preference
`debug_menu` is true. `ApiClient.java` gave the flow: `POST /v2/session` with the device id and
an `X-App-Key` header, a token read from the reply, then `Authorization: Bearer <token>` on the
other two. Each endpoint goes in the ledger with its file and line. A literal URL in a call is
enough for an endpoint, but this host is computed, so it is an algorithm result: it needs two
independent input/output pairs, such as two other strings run through the same decoder, before
`confirmed`.
