.PHONY: help install setup doctor demo run replay test clean

PROFILE ?= ransomware-affiliate
ENV     ?= hospital
OUT     ?= examples/ransomware-affiliate-hospital

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n",$$1,$$2}'

install:  ## install python deps (stdlib + sibling-repo deps + pytest)
	pip install --break-system-packages -r requirements.txt

setup:  ## clone the 7 sibling repos into vendor/ (skip if they are already next to this repo)
	bash scripts/setup_siblings.sh

doctor:  ## check that every sibling repository resolves
	python -m ptp doctor

demo:  ## full end-to-end run into $(OUT) (~1-2 min) and record the animated SVG
	python -m ptp run --profile $(PROFILE) --env $(ENV) --out $(OUT)
	python scripts/record_demo.py --run $(OUT)

run:  ## run into a timestamped runs/ directory
	python -m ptp run --profile $(PROFILE) --env $(ENV)

replay:  ## re-print the committed example scoreboard
	python -m ptp replay $(OUT)

test:  ## run the test suite (includes the slow end-to-end run)
	python -m pytest -q

clean:  ## remove run outputs and caches (keeps examples/)
	rm -rf runs .pytest_cache _benign
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
