#!/usr/bin/env bash
set -euo pipefail

# Updates prerelease versions for publishing by editing only the workspace root `Cargo.toml`:
# - [workspace.package].version
# - [workspace.dependencies.*] tables that have a `path = "..."` (set/replace `version = "..."`)

run="${GITHUB_RUN_NUMBER:-0}"
sha="${GITHUB_SHA:-unknown}"
sha7="${sha:0:7}"

file="Cargo.toml"

# Read base version from [workspace.package]
base="$(
  awk '
    $0 == "[workspace.package]" { in_pkg=1; next }
    /^\[/ { in_pkg=0 }
    in_pkg && $1=="version" && $2=="=" {
      gsub(/"/,"",$3);
      print $3;
      exit
    }
  ' "$file"
)"

if [[ -z "${base}" ]]; then
  echo "error: could not find [workspace.package] version in $file" >&2
  exit 1
fi

base="${base%%-*}"
new_ver="${base}-nightly.${run}.${sha7}"

tmp="$(mktemp)"
awk -v new_ver="$new_ver" '
  function emit_dep_block() {
    if (!in_dep) return
    if (dep_has_path && !dep_has_version) {
      dep_block[++dep_n] = "version = \"" new_ver "\"\n"
    }
    for (i=1; i<=dep_n; i++) printf "%s", dep_block[i]
    dep_n=0
    dep_has_path=0
    dep_has_version=0
  }

  # Start of a dependency block like: [workspace.dependencies.foo]
  /^\[workspace\.dependencies\.[^]]+\]$/ {
    emit_dep_block()
    in_pkg=0
    in_dep=1
    dep_block[++dep_n] = $0 "\n"
    next
  }

  # Any section header
  /^\[/ {
    emit_dep_block()
    in_dep=0
    in_pkg = ($0 == "[workspace.package]")
    print $0
    next
  }

  # Inside [workspace.package]
  in_pkg && $1=="version" && $2=="=" {
    print "version = \"" new_ver "\""
    next
  }

  # Inside a [workspace.dependencies.*] block: buffer and potentially modify
  in_dep {
    if ($1=="path" && $2=="=") dep_has_path=1
    if ($1=="version" && $2=="=") {
      dep_has_version=1
      dep_block[++dep_n] = "version = \"" new_ver "\"\n"
      next
    }
    dep_block[++dep_n] = $0 "\n"
    next
  }

  # Default passthrough
  { print $0 }

  END { emit_dep_block() }
' "$file" > "$tmp"

mv "$tmp" "$file"
echo "set workspace/package + workspace.dependencies versions to ${new_ver}"


