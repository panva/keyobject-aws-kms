#!/usr/bin/env bash
# Render the body for the generated dependency-bump pull request.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

if (( $# > 1 )); then
  echo "usage: $0 [base-ref]" >&2
  exit 2
fi

base=${1:-origin/main}
git rev-parse --verify "$base^{commit}" >/dev/null 2>&1 || {
  echo "dependency PR base is not a commit: $base" >&2
  exit 1
}

transitions=$(git log --reverse --format='%s' "$base..HEAD")
[[ -n $transitions ]] || {
  echo "dependency PR has no commits after $base" >&2
  exit 1
}

subjects=()
while IFS= read -r subject; do
  if [[ ! $subject =~ ^build:\ bump\ ([^[:space:]]+)\ from\ ([^[:space:]]+)\ to\ ([^[:space:]]+)$ ]]; then
    echo "unexpected dependency bump subject: $subject" >&2
    exit 1
  fi
  subjects+=("$subject")
done <<< "$transitions"

printf '%s\n\n' 'Opened weekly by `.github/workflows/vendored.yml`.'
printf '## Changes\n\n'
for subject in "${subjects[@]}"; do
  [[ $subject =~ ^build:\ bump\ ([^[:space:]]+)\ from\ ([^[:space:]]+)\ to\ ([^[:space:]]+)$ ]]
  printf -- '- Bump `%s` from `%s` to `%s`.\n' \
    "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
done
printf '\n%s\n\n' 'This branch is **reset from `main`** every week and force-pushed, so it is always exactly `main` plus one commit per dependency that moved. It is derived state: do not commit onto it, and expect history to be rewritten.'
printf '%s\n\n' '**Mark this ready for review to run CI.** It is opened as a draft, and this repository gates CI behind a non-draft pull request. The `ready_for_review` action is an explicit CI trigger.'
printf '%s\n' 'An `aws-sdk-cpp` bump moves vendored s2n. The build checks whether the local s2n compatibility patch is still applicable or can be removed.'
