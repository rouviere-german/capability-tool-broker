# Linux/CI convenience targets. Every target delegates to tasks.py, which is the single source
# of truth and also runs on Windows: `uv run python tasks.py <target>`.

UV ?= uv
TASK := $(UV) run python tasks.py
IMAGE ?= capability-tool-broker:local

.PHONY: install lint format typecheck test bench demo bandit pip-audit audit baseline record check docker-build compose-up compose-e2e

install:
	$(UV) sync --frozen

lint:
	$(TASK) lint

format:
	$(TASK) format

typecheck:
	$(TASK) typecheck

test:
	$(TASK) test

bench:
	$(TASK) bench

demo:
	$(TASK) demo

bandit:
	$(TASK) bandit

pip-audit:
	$(TASK) pip-audit

audit:
	$(TASK) audit

baseline:
	$(TASK) baseline

record:
	$(TASK) record

check:
	$(TASK) check

docker-build:
	docker build -t $(IMAGE) .

# Needs .env from `uv run capability-tool-broker keygen` and a signed manifest (see README).
compose-up:
	docker compose up --build --detach --wait

compose-e2e: compose-up
	docker compose run --rm agent-host e2e start
	docker compose exec -T approver capability-tool-broker approver review
	docker compose run --rm agent-host e2e resume
