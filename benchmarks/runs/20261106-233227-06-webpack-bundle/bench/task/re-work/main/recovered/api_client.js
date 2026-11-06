// Recovered API client for webshop/3.1 (module 255 = request core, 10 = auth, 633 = orders)
const BASE = "https://shop.example/api/v3";

async function request(path, { method = "GET", token, body } = {}) {
  const headers = { "Content-Type": "application/json", "X-Client": "webshop/3.1" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method, headers, body: body && JSON.stringify(body),
  });
  if (res.status === 401) throw new Error("session expired");
  return res.json();
}
const login = (username, password) =>
  request("/auth/login", { method: "POST", body: { username, password } });
const listOrders = (token) => request("/orders?limit=50", { token });
const cancelOrder = (token, id) => request(`/orders/${id}/cancel`, { method: "POST", token });
module.exports = { request, login, listOrders, cancelOrder };
