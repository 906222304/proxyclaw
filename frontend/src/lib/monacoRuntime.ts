// Loaded only when the user opens the raw configuration editor.
import 'monaco-editor/esm/nls.messages.zh-cn.js'
import * as monaco from 'monaco-editor/esm/vs/editor/editor.api.js'
import 'monaco-editor/esm/vs/language/json/monaco.contribution'
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import JsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker'

const scope = globalThis as typeof globalThis & {
  MonacoEnvironment?: { getWorker: (workerId: string, label: string) => Worker }
}
if (!scope.MonacoEnvironment) {
  scope.MonacoEnvironment = {
    getWorker(_workerId, label) {
      return label === 'json' ? new JsonWorker() : new EditorWorker()
    },
  }
}

export { monaco }
