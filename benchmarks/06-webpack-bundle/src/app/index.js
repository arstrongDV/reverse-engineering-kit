import { login } from "./api/auth.js";
import { listOrders, cancelOrder } from "./api/orders.js";
import { renderOrders } from "./ui/render.js";

async function start() {
  const session = await login("demo-user", "demo-pass");
  const orders = await listOrders(session.token);
  renderOrders(orders, (id) => cancelOrder(session.token, id));
}

start();
