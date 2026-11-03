// Loaded only when the user opens the raw configuration editor.
import 'monaco-editor/nls/lang/zh-cn.js'
import * as monaco from 'monaco-editor/editor/editor.api.js'
import 'monaco-editor/language/json/monaco.contribution'
import EditorWorker from 'monaco-editor/editor/editor.worker?worker'
import JsonWorker from 'monaco-editor/language/json/json.worker?worker'

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
