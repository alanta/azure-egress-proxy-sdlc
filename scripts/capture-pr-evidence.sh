#!/usr/bin/env bash
# Capture read-only evidence for pull requests in a subject repository, before PR state,
# check runs or logs change or expire. Writes nothing to the subject repository.
#
# Usage: scripts/capture-pr-evidence.sh <owner/repo> <out-dir> <pr-number>...
# Needs: gh (authenticated; read access is enough), jq.
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <owner/repo> <out-dir> <pr-number>..." >&2
  exit 2
fi

repo=$1 out=$2
shift 2

captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
default_branch=$(gh api "repos/$repo" --jq .default_branch)
default_sha=$(gh api "repos/$repo/commits/$default_branch" --jq .sha)
mkdir -p "$out"
manifest_entries=()

for n in "$@"; do
  dir="$out/$n"
  mkdir -p "$dir/jobs"

  gh api "repos/$repo/pulls/$n" > "$dir/pr.json"
  gh api "repos/$repo/pulls/$n/files" --paginate > "$dir/files.json"
  head=$(jq -r .head.sha "$dir/pr.json")

  # Full commit messages: Dependabot's updated-dependencies metadata lives here.
  gh api "repos/$repo/pulls/$n/commits" --paginate > "$dir/commits.json"
  gh pr diff "$n" --repo "$repo" > "$dir/diff.patch"
  gh api "repos/$repo/commits/$head/check-runs" --paginate > "$dir/check-runs.json"
  gh api "repos/$repo/actions/runs?head_sha=$head" > "$dir/workflow-runs.json"

  logs=()
  for run_id in $(jq -r '.workflow_runs[].id' "$dir/workflow-runs.json"); do
    gh api "repos/$repo/actions/runs/$run_id/jobs" --paginate > "$dir/jobs/run-$run_id.json"
    while IFS=$'\t' read -r job_id conclusion; do
      [[ $conclusion == skipped ]] && continue
      if gh api "repos/$repo/actions/jobs/$job_id/logs" > "$dir/jobs/$job_id.log" 2>/dev/null; then
        logs+=("$(jq -n --arg j "$job_id" --arg c "$conclusion" '{job: $j, conclusion: $c, log: "available"}')")
      else
        rm -f "$dir/jobs/$job_id.log"
        logs+=("$(jq -n --arg j "$job_id" --arg c "$conclusion" '{job: $j, conclusion: $c, log: "unavailable"}')")
      fi
    done < <(jq -r '.jobs[] | [.id, (.conclusion // .status)] | @tsv' "$dir/jobs/run-$run_id.json")
  done

  manifest_entries+=("$(jq -n --argjson n "$n" --arg head "$head" --arg state "$(jq -r .state "$dir/pr.json")" \
    --argjson logs "[$(IFS=,; echo "${logs[*]:-}")]" '{pr: $n, state: $state, head: $head, job_logs: $logs}')")
done

jq -n --arg repo "$repo" --arg at "$captured_at" --arg branch "$default_branch" --arg sha "$default_sha" \
  --argjson prs "[$(IFS=,; echo "${manifest_entries[*]}")]" \
  '{repository: $repo, captured_at: $at, default_branch: $branch, default_branch_commit: $sha, prs: $prs}' \
  > "$out/manifest.json"

echo "Captured ${#manifest_entries[@]} PRs into $out"
