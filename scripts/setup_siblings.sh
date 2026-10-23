#!/usr/bin/env bash
# Clone the seven sibling repositories into vendor/ so the pipeline can import
# them. Skip this entirely if the repos already sit next to this one (the
# default portfolio layout) or if PORTFOLIO_ROOT points at them - run
# `python -m ptp doctor` to check what resolves.
set -euo pipefail

OWNER="brooklynkid707-cmd"
REPOS=(
  ai-adversary-emulation-planner
  splunk-threat-detection-lab
  siem-from-scratch
  microsoft-sentinel-detection-engineering
  ai-soc-copilot
  ml-threat-detection
  soc-analyst-toolkit
)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="${HERE}/vendor"
mkdir -p "${VENDOR}"

echo "Cloning ${#REPOS[@]} sibling repositories into ${VENDOR}"
for repo in "${REPOS[@]}"; do
  dest="${VENDOR}/${repo}"
  if [ -d "${dest}/.git" ]; then
    echo "  [skip] ${repo} already present; pulling latest"
    git -C "${dest}" pull --ff-only || true
  else
    echo "  [clone] ${repo}"
    git clone --depth 1 "https://github.com/${OWNER}/${repo}.git" "${dest}"
  fi
done

echo
echo "Done. Verify with:  python -m ptp doctor"
