import { X } from 'lucide-react'
import { useState, type KeyboardEvent } from 'react'

export function TagInput({ value, onChange, placeholder, id }: {
  value: string[]
  onChange: (v: string[]) => void
  placeholder?: string
  id?: string
}) {
  const [text, setText] = useState('')

  const add = () => {
    const v = text.trim()
    if (v && !value.includes(v)) onChange([...value, v])
    setText('')
  }
  const remove = (i: number) => onChange(value.filter((_, j) => j !== i))
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      add()
    }
    if (e.key === 'Backspace' && !text && value.length > 0) remove(value.length - 1)
  }

  return (
    <div className="flex min-h-control cursor-text flex-wrap items-center gap-1 rounded-md bg-field px-1.5 py-1 transition-[background-color,box-shadow] duration-150 hover:bg-field-hover focus-within:bg-field focus-within:ring-1 focus-within:ring-inset focus-within:ring-primary">
      {value.map((tag, i) => (
        <button
          key={tag}
          type="button"
          onClick={() => remove(i)}
          title="删除"
          className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-0.5 tabular text-2xs transition-colors hover:text-destructive"
        >
          {tag} <X className="size-3" />
        </button>
      ))}
      <input
        id={id}
        value={text}
        onChange={e => setText(e.target.value)}
        onKeyDown={onKeyDown}
        onBlur={add}
        placeholder={value.length === 0 ? placeholder : ''}
        className="min-w-[120px] flex-1 tabular bg-transparent text-xs outline-none px-1 placeholder:text-faint"
      />
    </div>
  )
}
