export function renderOrders(orders, onCancel) {
  const list = document.createElement("ul");
  for (const order of orders) {
    const item = document.createElement("li");
    item.textContent = `${order.id}: ${order.total}`;
    item.addEventListener("click", () => onCancel(order.id));
    list.append(item);
  }
  document.body.append(list);
}
