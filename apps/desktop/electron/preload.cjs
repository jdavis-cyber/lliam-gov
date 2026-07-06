const { contextBridge, ipcRenderer, webUtils } = require('electron')

contextBridge.exposeInMainWorld('lliamDesktop', {
  getConnection: profile => ipcRenderer.invoke('lliam:connection', profile),
  revalidateConnection: () => ipcRenderer.invoke('lliam:connection:revalidate'),
  touchBackend: profile => ipcRenderer.invoke('lliam:backend:touch', profile),
  getGatewayWsUrl: profile => ipcRenderer.invoke('lliam:gateway:ws-url', profile),
  openSessionWindow: (sessionId, opts) => ipcRenderer.invoke('lliam:window:openSession', sessionId, opts),
  openNewSessionWindow: () => ipcRenderer.invoke('lliam:window:openNewSession'),
  petOverlay: {
    // Main renderer → main process: window lifecycle + drag. `request` is
    // `{ bounds, screen }`; resolves with the screen bounds it actually used.
    open: request => ipcRenderer.invoke('lliam:pet-overlay:open', request),
    close: () => ipcRenderer.invoke('lliam:pet-overlay:close'),
    setBounds: bounds => ipcRenderer.send('lliam:pet-overlay:set-bounds', bounds),
    setIgnoreMouse: ignore => ipcRenderer.send('lliam:pet-overlay:ignore-mouse', ignore),
    // Flip the overlay focusable (and focus it) while the composer needs keys.
    setFocusable: focusable => ipcRenderer.send('lliam:pet-overlay:set-focusable', focusable),
    // Main renderer → overlay (forwarded by main): push the latest pet state.
    pushState: payload => ipcRenderer.send('lliam:pet-overlay:state', payload),
    // Overlay → main renderer (forwarded by main): pop back in / composer submit.
    control: payload => ipcRenderer.send('lliam:pet-overlay:control', payload),
    // Overlay subscribes to state pushes.
    onState: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('lliam:pet-overlay:state', listener)
      return () => ipcRenderer.removeListener('lliam:pet-overlay:state', listener)
    },
    // Main renderer subscribes to overlay control messages.
    onControl: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('lliam:pet-overlay:control', listener)
      return () => ipcRenderer.removeListener('lliam:pet-overlay:control', listener)
    }
  },
  getBootProgress: () => ipcRenderer.invoke('lliam:boot-progress:get'),
  getConnectionConfig: profile => ipcRenderer.invoke('lliam:connection-config:get', profile),
  saveConnectionConfig: payload => ipcRenderer.invoke('lliam:connection-config:save', payload),
  applyConnectionConfig: payload => ipcRenderer.invoke('lliam:connection-config:apply', payload),
  testConnectionConfig: payload => ipcRenderer.invoke('lliam:connection-config:test', payload),
  probeConnectionConfig: remoteUrl => ipcRenderer.invoke('lliam:connection-config:probe', remoteUrl),
  oauthLoginConnectionConfig: remoteUrl => ipcRenderer.invoke('lliam:connection-config:oauth-login', remoteUrl),
  oauthLogoutConnectionConfig: remoteUrl => ipcRenderer.invoke('lliam:connection-config:oauth-logout', remoteUrl),
  profile: {
    get: () => ipcRenderer.invoke('lliam:profile:get'),
    set: name => ipcRenderer.invoke('lliam:profile:set', name)
  },
  api: request => ipcRenderer.invoke('lliam:api', request),
  notify: payload => ipcRenderer.invoke('lliam:notify', payload),
  requestMicrophoneAccess: () => ipcRenderer.invoke('lliam:requestMicrophoneAccess'),
  readFileDataUrl: filePath => ipcRenderer.invoke('lliam:readFileDataUrl', filePath),
  readFileText: filePath => ipcRenderer.invoke('lliam:readFileText', filePath),
  selectPaths: options => ipcRenderer.invoke('lliam:selectPaths', options),
  writeClipboard: text => ipcRenderer.invoke('lliam:writeClipboard', text),
  saveImageFromUrl: url => ipcRenderer.invoke('lliam:saveImageFromUrl', url),
  saveImageBuffer: (data, ext) => ipcRenderer.invoke('lliam:saveImageBuffer', { data, ext }),
  saveClipboardImage: () => ipcRenderer.invoke('lliam:saveClipboardImage'),
  getPathForFile: file => {
    try {
      return webUtils.getPathForFile(file) || ''
    } catch {
      return ''
    }
  },
  normalizePreviewTarget: (target, baseDir) => ipcRenderer.invoke('lliam:normalizePreviewTarget', target, baseDir),
  watchPreviewFile: url => ipcRenderer.invoke('lliam:watchPreviewFile', url),
  stopPreviewFileWatch: id => ipcRenderer.invoke('lliam:stopPreviewFileWatch', id),
  setTitleBarTheme: payload => ipcRenderer.send('lliam:titlebar-theme', payload),
  setNativeTheme: mode => ipcRenderer.send('lliam:native-theme', mode),
  setTranslucency: payload => ipcRenderer.send('lliam:translucency', payload),
  setPreviewShortcutActive: active => ipcRenderer.send('lliam:previewShortcutActive', Boolean(active)),
  openExternal: url => ipcRenderer.invoke('lliam:openExternal', url),
  openPreviewInBrowser: url => ipcRenderer.invoke('lliam:openPreviewInBrowser', url),
  fetchLinkTitle: url => ipcRenderer.invoke('lliam:fetchLinkTitle', url),
  sanitizeWorkspaceCwd: cwd => ipcRenderer.invoke('lliam:workspace:sanitize', cwd),
  settings: {
    getDefaultProjectDir: () => ipcRenderer.invoke('lliam:setting:defaultProjectDir:get'),
    setDefaultProjectDir: dir => ipcRenderer.invoke('lliam:setting:defaultProjectDir:set', dir),
    pickDefaultProjectDir: () => ipcRenderer.invoke('lliam:setting:defaultProjectDir:pick')
  },
  revealLogs: () => ipcRenderer.invoke('lliam:logs:reveal'),
  getRecentLogs: () => ipcRenderer.invoke('lliam:logs:recent'),
  readDir: dirPath => ipcRenderer.invoke('lliam:fs:readDir', dirPath),
  gitRoot: startPath => ipcRenderer.invoke('lliam:fs:gitRoot', startPath),
  revealPath: targetPath => ipcRenderer.invoke('lliam:fs:reveal', targetPath),
  renamePath: (targetPath, newName) => ipcRenderer.invoke('lliam:fs:rename', targetPath, newName),
  writeTextFile: (filePath, content) => ipcRenderer.invoke('lliam:fs:writeText', filePath, content),
  trashPath: targetPath => ipcRenderer.invoke('lliam:fs:trash', targetPath),
  git: {
    worktreeList: repoPath => ipcRenderer.invoke('lliam:git:worktreeList', repoPath),
    worktreeAdd: (repoPath, options) => ipcRenderer.invoke('lliam:git:worktreeAdd', repoPath, options),
    worktreeRemove: (repoPath, worktreePath, options) =>
      ipcRenderer.invoke('lliam:git:worktreeRemove', repoPath, worktreePath, options),
    branchSwitch: (repoPath, branch) => ipcRenderer.invoke('lliam:git:branchSwitch', repoPath, branch),
    branchList: repoPath => ipcRenderer.invoke('lliam:git:branchList', repoPath),
    repoStatus: repoPath => ipcRenderer.invoke('lliam:git:repoStatus', repoPath),
    fileDiff: (repoPath, filePath) => ipcRenderer.invoke('lliam:git:fileDiff', repoPath, filePath),
    scanRepos: (roots, options) => ipcRenderer.invoke('lliam:git:scanRepos', roots, options),
    review: {
      list: (repoPath, scope, baseRef) => ipcRenderer.invoke('lliam:git:review:list', repoPath, scope, baseRef),
      diff: (repoPath, filePath, scope, baseRef, staged) =>
        ipcRenderer.invoke('lliam:git:review:diff', repoPath, filePath, scope, baseRef, staged),
      stage: (repoPath, filePath) => ipcRenderer.invoke('lliam:git:review:stage', repoPath, filePath),
      unstage: (repoPath, filePath) => ipcRenderer.invoke('lliam:git:review:unstage', repoPath, filePath),
      revert: (repoPath, filePath) => ipcRenderer.invoke('lliam:git:review:revert', repoPath, filePath),
      revParse: (repoPath, ref) => ipcRenderer.invoke('lliam:git:review:revParse', repoPath, ref),
      commit: (repoPath, message, push) => ipcRenderer.invoke('lliam:git:review:commit', repoPath, message, push),
      commitContext: repoPath => ipcRenderer.invoke('lliam:git:review:commitContext', repoPath),
      push: repoPath => ipcRenderer.invoke('lliam:git:review:push', repoPath),
      shipInfo: repoPath => ipcRenderer.invoke('lliam:git:review:shipInfo', repoPath),
      createPr: repoPath => ipcRenderer.invoke('lliam:git:review:createPr', repoPath)
    }
  },
  terminal: {
    dispose: id => ipcRenderer.invoke('lliam:terminal:dispose', id),
    resize: (id, size) => ipcRenderer.invoke('lliam:terminal:resize', id, size),
    start: options => ipcRenderer.invoke('lliam:terminal:start', options),
    write: (id, data) => ipcRenderer.invoke('lliam:terminal:write', id, data),
    onData: (id, callback) => {
      const channel = `hermes:terminal:${id}:data`
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on(channel, listener)
      return () => ipcRenderer.removeListener(channel, listener)
    },
    onExit: (id, callback) => {
      const channel = `hermes:terminal:${id}:exit`
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on(channel, listener)
      return () => ipcRenderer.removeListener(channel, listener)
    }
  },
  onClosePreviewRequested: callback => {
    const listener = () => callback()
    ipcRenderer.on('lliam:close-preview-requested', listener)
    return () => ipcRenderer.removeListener('lliam:close-preview-requested', listener)
  },
  onOpenUpdatesRequested: callback => {
    const listener = () => callback()
    ipcRenderer.on('lliam:open-updates', listener)
    return () => ipcRenderer.removeListener('lliam:open-updates', listener)
  },
  onDeepLink: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('lliam:deep-link', listener)
    return () => ipcRenderer.removeListener('lliam:deep-link', listener)
  },
  signalDeepLinkReady: () => ipcRenderer.invoke('lliam:deep-link-ready'),
  onWindowStateChanged: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('lliam:window-state-changed', listener)
    return () => ipcRenderer.removeListener('lliam:window-state-changed', listener)
  },
  onFocusSession: callback => {
    const listener = (_event, sessionId) => callback(sessionId)
    ipcRenderer.on('lliam:focus-session', listener)
    return () => ipcRenderer.removeListener('lliam:focus-session', listener)
  },
  onNotificationAction: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('lliam:notification-action', listener)
    return () => ipcRenderer.removeListener('lliam:notification-action', listener)
  },
  onPreviewFileChanged: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('lliam:preview-file-changed', listener)
    return () => ipcRenderer.removeListener('lliam:preview-file-changed', listener)
  },
  onBackendExit: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('lliam:backend-exit', listener)
    return () => ipcRenderer.removeListener('lliam:backend-exit', listener)
  },
  onPowerResume: callback => {
    const listener = () => callback()
    ipcRenderer.on('lliam:power-resume', listener)
    return () => ipcRenderer.removeListener('lliam:power-resume', listener)
  },
  onBootProgress: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('lliam:boot-progress', listener)
    return () => ipcRenderer.removeListener('lliam:boot-progress', listener)
  },
  // First-launch bootstrap progress -- emitted by the install.ps1 stage
  // runner in main.cjs (apps/desktop/electron/bootstrap-runner.cjs).
  // Renderer's install overlay subscribes to live events and queries the
  // current snapshot via getBootstrapState() to recover after a devtools
  // reload mid-bootstrap.
  getBootstrapState: () => ipcRenderer.invoke('lliam:bootstrap:get'),
  resetBootstrap: () => ipcRenderer.invoke('lliam:bootstrap:reset'),
  repairBootstrap: () => ipcRenderer.invoke('lliam:bootstrap:repair'),
  cancelBootstrap: () => ipcRenderer.invoke('lliam:bootstrap:cancel'),
  onBootstrapEvent: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('lliam:bootstrap:event', listener)
    return () => ipcRenderer.removeListener('lliam:bootstrap:event', listener)
  },
  getVersion: () => ipcRenderer.invoke('lliam:version'),
  getRemoteDisplayReason: () => ipcRenderer.invoke('lliam:get-remote-display-reason'),
  uninstall: {
    summary: () => ipcRenderer.invoke('lliam:uninstall:summary'),
    run: mode => ipcRenderer.invoke('lliam:uninstall:run', { mode })
  },
  updates: {
    check: () => ipcRenderer.invoke('lliam:updates:check'),
    apply: opts => ipcRenderer.invoke('lliam:updates:apply', opts),
    getBranch: () => ipcRenderer.invoke('lliam:updates:branch:get'),
    setBranch: name => ipcRenderer.invoke('lliam:updates:branch:set', name),
    onProgress: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('lliam:updates:progress', listener)
      return () => ipcRenderer.removeListener('lliam:updates:progress', listener)
    }
  },
  themes: {
    fetchMarketplace: id => ipcRenderer.invoke('lliam:vscode-theme:fetch', id),
    searchMarketplace: query => ipcRenderer.invoke('lliam:vscode-theme:search', query)
  }
})
