// Lazily loaded: CodeMirror lives only in this chunk.
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands'
import { json, jsonParseLinter } from '@codemirror/lang-json'
import {
  bracketMatching, defaultHighlightStyle, foldGutter, foldKeymap, indentOnInput, syntaxHighlighting,
} from '@codemirror/language'
import { lintGutter, linter } from '@codemirror/lint'
import { Compartment, EditorState } from '@codemirror/state'
import { oneDark } from '@codemirror/theme-one-dark'
import {
  EditorView, drawSelection, highlightActiveLine, highlightActiveLineGutter, keymap, lineNumbers,
} from '@codemirror/view'
import { useEffect, useRef } from 'react'

const baseTheme = EditorView.theme({
  '&': { height: '100%', fontSize: '13px', backgroundColor: 'var(--card)' },
  '.cm-scroller': { fontFamily: 'var(--font-mono)', lineHeight: '1.6' },
  '.cm-gutters': { backgroundColor: 'var(--card)', border: 'none', color: 'var(--muted-foreground)' },
  '.cm-content': { padding: '8px 0' },
  '&.cm-focused': { outline: 'none' },
})

const lightTheme = [syntaxHighlighting(defaultHighlightStyle, { fallback: true })]
const darkTheme = [oneDark, EditorView.theme({ '&': { backgroundColor: 'var(--card)' }, '.cm-gutters': { backgroundColor: 'var(--card)' } }, { dark: true })]

export default function JsonEditor({ value, onChange, onSave, dark }: {
  value: string
  onChange: (v: string) => void
  onSave: () => void
  dark: boolean
}) {
  const host = useRef<HTMLDivElement>(null)
  const view = useRef<EditorView | null>(null)
  const theme = useRef(new Compartment())
  // Latest callbacks without recreating the editor.
  const cb = useRef({ onChange, onSave })
  cb.current = { onChange, onSave }

  useEffect(() => {
    const state = EditorState.create({
      doc: value,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        foldGutter(),
        history(),
        drawSelection(),
        indentOnInput(),
        bracketMatching(),
        highlightActiveLine(),
        EditorState.tabSize.of(2),
        EditorView.lineWrapping,
        json(),
        linter(jsonParseLinter()),
        lintGutter(),
        keymap.of([
          { key: 'Mod-s', preventDefault: true, run: () => { cb.current.onSave(); return true } },
          indentWithTab,
          ...defaultKeymap,
          ...historyKeymap,
          ...foldKeymap,
        ]),
        baseTheme,
        theme.current.of(dark ? darkTheme : lightTheme),
        EditorView.updateListener.of(u => {
          if (u.docChanged) cb.current.onChange(u.state.doc.toString())
        }),
      ],
    })
    view.current = new EditorView({ state, parent: host.current! })
    return () => {
      view.current?.destroy()
      view.current = null
    }
    // The editor is created once; value/dark updates are dispatched below.
  }, [])

  useEffect(() => {
    const v = view.current
    if (v && v.state.doc.toString() !== value) {
      v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } })
    }
  }, [value])

  useEffect(() => {
    view.current?.dispatch({ effects: theme.current.reconfigure(dark ? darkTheme : lightTheme) })
  }, [dark])

  return <div ref={host} className="h-full min-h-[300px] overflow-hidden" />
}
