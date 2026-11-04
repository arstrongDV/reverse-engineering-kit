const BASE_URL = "https://shop.example/api/v3";

export async function request(path, { method = "GET", token, body } = {}) {
  const headers = { "Content-Type": "application/json", "X-Client": "webshop/3.1" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const reply = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body && JSON.stringify(body),
  });
  if (reply.status === 401) {
    throw new Error("session expired");
  }
  return reply.json();
}
