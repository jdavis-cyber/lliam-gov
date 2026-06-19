#!/bin/bash
# Point Lliam-GOV at a project folder for read/RAG (or list/clear).
#   lliam-project /path/to/project   # set (replaces)
#   lliam-project add /path/...      # append another
#   lliam-project list               # show current
#   lliam-project clear              # remove all
F="$HOME/.lliam-gov/.bridge_project"

resolve() { cd "$1" 2>/dev/null && pwd; }

case "${1:-list}" in
  list|"")
    echo "Lliam project folder(s):"; { [ -s "$F" ] && cat "$F"; } || echo "  (none)";;
  clear)
    : > "$F"; echo "cleared";;
  add)
    rp=$(resolve "$2") || { echo "not a directory: $2"; exit 1; }
    grep -qxF "$rp" "$F" 2>/dev/null || echo "$rp" >> "$F"
    echo "added: $rp"; echo "now reading:"; cat "$F";;
  *)
    rp=$(resolve "$1") || { echo "not a directory: $1"; exit 1; }
    printf '%s\n' "$rp" > "$F"
    echo "Lliam will read (RAG): $rp";;
esac
