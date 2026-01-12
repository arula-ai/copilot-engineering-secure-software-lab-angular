# Lab Action Guide

Follow these lean steps. After each stage, run Summarizer Mode with the Hand-Off prompt so progress lands in `docs/workflow-tracker.md`.

## Quick Reference

| Stage | Primary Modes | Core Artifacts / Commands |
| --- | --- | --- |
| 0 | Agent | `./scripts/setup-lab.sh`, `npm run start` |
| 1 | Agent → Testing | `.github/copilot-instructions.md`, `npm run lint`, `npm run test` |
| 2 | Planning → Verification Agent → Agent | `docs/vulnerability-guide.md`, `docs/test-coverage.md`, plan.md |
| 3 | Agent ↔ Need Review | `src/app/**`, `VULNERABILITIES.md`, `FIXES.md` |
| 4 | Planning → Testing → Agent | `docs/testing-guide.md`, `npm run test:coverage`, `docs/test-coverage.md` |
| 5 | Planning → Verification Agent → Agent ↔ Need Review | `docs/secure-features-guide.md`, feature specs |
| 6 | Testing → Agent | `npm run lint`, `npm run lint:security`, `npm run test:coverage`, `npm audit --audit-level=high`, `./scripts/generate-report.sh` |
| 7 | Agent ↔ Need Review | `homework/README.md` |
| 8 | Verification Agent → Agent ↔ Need Review | `SECURITY.md`, `homework/GRADING_RUBRIC.md`, PR template |

## Stage 0 – Environment Setup
- Agent Mode: `#runInTerminal #setup-lab.sh`, make sure both chat variables are actually linked if copying/pasting
- Agent Mode: `#runInTerminal npm run start` (initial build issues are fine)
- Hand-Off: summarize setup status and blockers, you'll notice it isn't able to run the editFile tool. This is on purpose; You should add it yourself then re-run the /hand-off command

## Stage 1 – Governance Alignment
- First, make sure that you are still inside of Agent mode
- Read `.github/copilot-instructions.md` and each chatmode file
- Inspect available tools (wrench icon) without changing settings
- Testing Mode: run `npm run lint` and `npm run test:coverage`; log assumptions in `docs/test-coverage.md`, we actually don't need to type `#runInTerminal` every time, each tool has a prompt associated with it that tells copilot when it can make use of it, the testing chatmode also tells it this
- Hand-Off: note guardrail highlights, command outcomes, gaps

## Stage 2 – Baseline Assessment
- Planning Mode: review `#vulnerability-guide.md` and current coverage
- Verification Agent: sanity-check the remediation plan against guardrails
- Agent Mode: capture file targets, risk notes, evidence needs
- Hand-Off: record the approved plan and open questions; save/update `docs/plans/plan.md`

## Stage 3 – Remediation
- Agent Mode: implement fixes in `src/app/**` referencing the plan
- Need Review Mode: request feedback per change slice; fold responses back in Agent Mode
- Agent Mode: update `VULNERABILITIES.md` / `FIXES.md` as fixes ship
- Hand-Off: summarize files touched, decisions made, pending follow-ups

## Stage 4 – Security Test Generation
- Planning Mode (optional): outline missing security coverage using `#testing-guide.md`
- Testing Mode: run `npm run test:coverage` until ≥80% or documented rationale
- Agent Mode: capture coverage deltas and evidence paths in `#test-coverage.md`
- Hand-Off: log executed suites, pass/fail status, remaining test work

## Stage 5 – Secure Feature Implementation
- Planning Mode: break down required feature changes from `#secure-features-guide.md`
- Verification Agent: confirm the feature plan satisfies guardrails
- Agent Mode: build the feature, referencing plan in chat variable and any other files that you deem relevant to the implementation.
- Review Mode: Need Review Mode for review-ready slices, again, referencing any changed files.
- Hand-Off: capture implemented pieces, validation outcomes, and TODOs

## Stage 6 – Governance Validation & Reporting
- Testing Mode: run `npm run lint`, `npm run lint:security`, `npm run test:coverage`, `npm audit --audit-level=high` (or `./scripts/run-all-checks.sh`)
- Testing Mode: execute `./scripts/generate-report.sh`; inspect `governance-report.md` in Agent Mode
- Agent Mode: refresh `VULNERABILITIES.md`, `FIXES.md`, `COPILOT_USAGE.md` with final status
- Hand-Off: state command results, report readiness, outstanding risks

## Stage 7 – Homework & Extras
- Agent Mode: complete `homework/README.md` tasks; involve Need Review Mode if validation is needed
- Agent Mode: gather artifacts for bonus work
- Hand-Off: document optional work finished and items left for later

## Stage 8 – Prepare Submission
- Verification Agent: walk `SECURITY.md` checklist and close gaps
- Agent Mode: review `homework/GRADING_RUBRIC.md`, push branch, open PR
- Need Review Mode: fill the PR template with governance evidence
- Hand-Off: confirm submission state, linked artifacts, next reviewer actions

## Mode Loop Reminder
- Planning → Verification Agent → Agent → Need Review → Testing
- Use the Summarizer Hand-Off after each stage so `docs/workflow-tracker.md` stays current without direct edits.
