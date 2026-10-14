#!/usr/bin/env bash
# remind.sh EXPIRY_FILE SOON_DAYS
# Opens one GitHub issue for each item in EXPIRY_FILE that's due within SOON_DAYS, or overdue.
# Issues are matched by title, so running it every week doesn't open duplicates.
# Needs GITHUB_REPOSITORY and GH_TOKEN. YQ overrides the yq command; DRY_RUN=1 only prints.
set -euo pipefail
file=$1
soon=$2
today=$(date -u +%F)
read -ra yq <<<"${YQ:-yq}"
open_titles=$(gh api "repos/$GITHUB_REPOSITORY/issues?state=open&per_page=100" \
  --jq '.[] | select(.pull_request == null) | .title')

"${yq[@]}" -o=json '.items' <"$file" | jq -c '.[]' | while read -r item; do
  what=$(jq -r .what <<<"$item")
  due=$(jq -r .due <<<"$item")
  action=$(jq -r .action <<<"$item")
  owner=$(jq -r .owner <<<"$item")
  days=$((($(date -u -d "$due" +%s) - $(date -u -d "$today" +%s)) / 86400))
  if [ "$days" -gt "$soon" ]; then
    echo "later: $what ($due, in $days days)"
    continue
  fi
  title="Reminder: $what ($due)"
  if grep -qxF "$title" <<<"$open_titles"; then
    echo "already open: $title"
    continue
  fi
  if [ "$days" -lt 0 ]; then when="$((-days)) days overdue"; else when="in $days days"; fi
  if [ "${DRY_RUN:-}" = 1 ]; then
    echo "would open: $title, $when"
    continue
  fi
  body=$(printf '@%s %s is due **%s** (%s).\n\nWhat to do: %s\n\nOpened by the Upkeep workflow from `infra/expiry.yaml`. When it is done, move the date in that file and close this issue.' \
    "$owner" "$what" "$due" "$when" "$action")
  gh api "repos/$GITHUB_REPOSITORY/issues" -f title="$title" -f body="$body" --jq '"opened: \(.html_url)"' </dev/null
done
