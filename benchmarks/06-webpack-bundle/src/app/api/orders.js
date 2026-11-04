import { request } from "./client.js";

export function listOrders(token) {
  return request("/orders?limit=50", { token });
}

export function cancelOrder(token, id) {
  return request(`/orders/${id}/cancel`, { method: "POST", token });
}
