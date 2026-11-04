const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("node:path");
const store = require("./lib/store.js");

function createWindow() {
  const window = new BrowserWindow({
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true },
  });
  window.loadFile("index.html");
}

ipcMain.handle("notes:list", () => store.list());
ipcMain.handle("notes:save", (event, note) => store.save(note));
ipcMain.handle("notes:delete", (event, id) => store.remove(id));
ipcMain.on("window:minimize", (event) => BrowserWindow.fromWebContents(event.sender).minimize());
ipcMain.handle("app:version", () => app.getVersion());

app.whenReady().then(createWindow);
