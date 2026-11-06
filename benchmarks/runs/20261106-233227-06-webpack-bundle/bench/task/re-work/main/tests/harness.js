// usage: node harness.js <orig|model> <scenario>; stubs fetch/document, prints recorded calls as JSON
const fs = require("fs"), path = require("path");
const [, , which, scenario] = process.argv;
const calls = [];
globalThis.fetch = async (url, opts) => {
  calls.push({ url, method: opts.method, headers: opts.headers, body: opts.body });
  if (scenario === "expired" && url.includes("/orders")) return { status: 401, json: async () => ({}) };
  return { status: 200, json: async () => url.includes("login") ? { token: "TOK" } : [{ id: 7, total: 9 }] };
};
const clicks = [];
const el = () => ({ append() {}, set textContent(v) { calls.push({ text: v }); }, addEventListener(_, f) { clicks.push(f); } });
globalThis.document = { createElement: el, body: { append() {} } };
(async () => {
  let err = null;
  process.on("unhandledRejection", (e) => { err = e.message; });
  if (which === "orig") {
    const root = path.resolve(__dirname, "../original/main.js");
    eval(fs.readFileSync(root, "utf8"));
    await new Promise((r) => setTimeout(r, 50));
    if (clicks[0]) { clicks[0](); await new Promise((r) => setTimeout(r, 50)); }
  } else {
    const c = require("../recovered/api_client.js");
    try {
      const t = await c.login("demo-user", "demo-pass");
      const o = await c.listOrders(t.token);
      if (o) await c.cancelOrder(t.token, o[0].id);
    } catch (e) { err = e.message; }
  }
  console.log(JSON.stringify({ calls: calls.filter((c) => c.url), err }));
})();
