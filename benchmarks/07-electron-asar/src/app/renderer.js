async function refresh() {
  const list = document.querySelector("#notes");
  list.replaceChildren();
  for (const note of await window.notes.list()) {
    const item = document.createElement("li");
    item.textContent = note.text;
    list.append(item);
  }
}

document.querySelector("#save").addEventListener("click", async () => {
  await window.notes.save({ text: document.querySelector("#text").value });
  await refresh();
});

refresh();
