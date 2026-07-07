const { app, BrowserWindow, Tray, Menu, screen, shell } = require('electron');
const path = require('path');
const bridge = require('./backend/ipc-bridge');

let mainWindow = null;
let toolbarWindow = null;
let tray = null;
let isQuitting = false;

const alive = (win) => win && !win.isDestroyed();

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    autoHideMenuBar: true,
    show: false,
  });

  mainWindow.loadURL('http://localhost:3001');
  mainWindow.once('ready-to-show', () => mainWindow.show());

  // Hide to tray instead of quitting
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });
}

function createToolbarWindow() {
  const { width } = screen.getPrimaryDisplay().workAreaSize;

  toolbarWindow = new BrowserWindow({
    width: 390,
    height: 38,
    x: width - 450,
    y: 10,
    frame: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    transparent: true,
    backgroundColor: '#00000000',
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  toolbarWindow.loadURL('http://localhost:3001/toolbar');
  toolbarWindow.once('ready-to-show', () => toolbarWindow.showInactive());

  // Hide instead of close
  toolbarWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      toolbarWindow.hide();
    }
  });
}

function buildContextMenu() {
  const toolbarVisible = alive(toolbarWindow) && toolbarWindow.isVisible();
  return Menu.buildFromTemplate([
    {
      label: 'Show Dashboard',
      click: () => {
        if (!alive(mainWindow)) return;
        mainWindow.show();
        mainWindow.focus();
      },
    },
    {
      label: toolbarVisible ? 'Hide Toolbar' : 'Show Toolbar',
      click: () => {
        if (!alive(toolbarWindow)) return;
        if (toolbarWindow.isVisible()) {
          toolbarWindow.hide();
        } else {
          toolbarWindow.showInactive();
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => { isQuitting = true; app.quit(); },
    },
  ]);
}

function createTray() {
  tray = new Tray(path.join(__dirname, 'assets', 'tray-icon.png'));
  tray.setToolTip('Network Detector - running in background');

  // Left-click: show/focus dashboard
  tray.on('click', () => {
    if (!alive(mainWindow)) return;
    if (mainWindow.isVisible()) {
      mainWindow.focus();
    } else {
      mainWindow.show();
    }
  });

  // Right-click: context menu
  tray.on('right-click', () => tray.popUpContextMenu(buildContextMenu()));
}

app.on('ready', () => {
  try {
    require('./backend/server.js');
  } catch (err) {
    console.error('Failed to start backend server:', err);
  }

  setTimeout(() => {
    createMainWindow();
    createToolbarWindow();
    createTray();

    // Bridge: toolbar control handlers (called from Express routes)
    bridge.on('toolbar:get-status', (cb) => {
      cb({
        visible: alive(toolbarWindow) && toolbarWindow.isVisible(),
        pinned: alive(toolbarWindow) ? toolbarWindow.isAlwaysOnTop() : true,
        opacity: alive(toolbarWindow) ? Math.round(toolbarWindow.getOpacity() * 100) : 100,
      });
    });

    bridge.on('toolbar:toggle', () => {
      if (!alive(toolbarWindow)) return;
      if (toolbarWindow.isVisible()) {
        toolbarWindow.hide();
      } else {
        toolbarWindow.showInactive();
      }
    });

    bridge.on('toolbar:pin-toggle', () => {
      if (!alive(toolbarWindow)) return;
      const next = !toolbarWindow.isAlwaysOnTop();
      toolbarWindow.setAlwaysOnTop(next, next ? 'floating' : undefined);
    });

    bridge.on('toolbar:set-opacity', (opacity) => {
      if (!alive(toolbarWindow)) return;
      toolbarWindow.setOpacity(opacity);
    });

    // Open a URL in the system default browser (used for router admin page)
    bridge.on('shell:open-external', (url) => {
      shell.openExternal(url).catch(() => {});
    });
  }, 1000);
});

// Keep alive in tray when all windows are closed
app.on('window-all-closed', () => { /* intentional no-op */ });

app.on('before-quit', () => { isQuitting = true; });
