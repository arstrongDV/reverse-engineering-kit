import { request } from "./client.js";

export function login(username, password) {
  return request("/auth/login", { method: "POST", body: { username, password } });
}
