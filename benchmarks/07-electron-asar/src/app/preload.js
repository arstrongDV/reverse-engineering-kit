const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("notes", {
  list: () => ipcRenderer.invoke("notes:list"),
  save: (note) => ipcRenderer.invoke("notes:save", note),
  remove: (id) => ipcRenderer.invoke("notes:delete", id),
  minimize: () => ipcRenderer.send("window:minimize"),
  version: () => ipcRenderer.invoke("app:version"),
});
