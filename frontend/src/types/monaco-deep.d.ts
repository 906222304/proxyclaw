// Deep-path imports from monaco-editor. The package's `exports` field uses a
// catch-all `"./*": "./esm/vs/*.js"` which Vite handles fine but TypeScript's module
// resolver needs an explicit declaration for type checking.

declare module 'monaco-editor/editor/editor.api.js' {
  export * from 'monaco-editor'
}

declare module 'monaco-editor/language/json/monaco.contribution' {
  const _side_effects: void
  export default _side_effects
}

declare module 'monaco-editor/editor/editor.worker?worker' {
  const WorkerClass: { new (): Worker }
  export default WorkerClass
}

declare module 'monaco-editor/language/json/json.worker?worker' {
  const WorkerClass: { new (): Worker }
  export default WorkerClass
}

declare module 'monaco-editor/nls/lang/zh-cn.js' {
  const _side_effects: void
  export default _side_effects
}
