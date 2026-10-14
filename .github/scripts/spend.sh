#!/usr/bin/env bash
# spend.sh LIMIT
# Opens a GitHub issue when Azure's spend for the month so far is over LIMIT, in the billing
# currency (INR here). If the cost API fails, so does this script; that never counts as zero.
# Needs an Azure login (az), GITHUB_REPOSITORY and GH_TOKEN. NOTIFY defaults to sayanx64.
set -euo pipefail
limit=$1
# az rest fills in {subscriptionId} from the current login.
out=$(az rest -m post \
  -u "/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/query?api-version=2023-03-01" \
  --body '{"type":"ActualCost","timeframe":"MonthToDate","dataset":{"granularity":"None","aggregation":{"totalCost":{"name":"Cost","function":"Sum"}}}}' \
  -o json)
# No rows means nothing has been billed yet this month.
cost=$(jq -r '(.properties.rows[0][0] // 0) * 100 | round / 100' <<<"$out")
currency=$(jq -r '.properties.rows[0][1] // "INR"' <<<"$out")
echo "Azure spend this month: $cost $currency (limit $limit)"
if ! awk -v c="$cost" -v l="$limit" 'BEGIN { exit !(c > l) }'; then
  exit 0
fi
title="Azure spending is high ($(date -u +%Y-%m))"
open_titles=$(gh api "repos/$GITHUB_REPOSITORY/issues?state=open&per_page=100" --jq '.[].title')
if grep -qxF "$title" <<<"$open_titles"; then
  echo "already open: $title"
  exit 0
fi
body=$(printf '@%s Azure has spent **%s %s** this month, over the %s limit.\n\nSee "Azure spending is high" in `infra/RUNBOOK.md`.' \
  "${NOTIFY:-sayanx64}" "$cost" "$currency" "$limit")
gh api "repos/$GITHUB_REPOSITORY/issues" -f title="$title" -f body="$body" --jq '"opened: \(.html_url)"'
