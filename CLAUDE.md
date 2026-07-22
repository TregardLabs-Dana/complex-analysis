# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This repository supports complex security analysis work, built around two workflows:

1. **Threat intel processing** — ingest threat intel reports, extract TTPs (tactics, techniques, and
   procedures), and turn them into simulation plans.
2. **Multi-source investigation** — correlate endpoint and cloud logs to investigate and reconstruct
   activity across an environment.

The overarching goal is repeatable workflows for complex analysis tasks — not one-off scripts, but
processes that can be re-run consistently as new reports or incidents come in.

## Log sources

Investigations and correlation work in this repo draw on:

- Windows Security events
- Sysmon events
- Azure AD sign-in logs
- Azure AD audit logs

When correlating across sources, keep in mind they use different timestamp formats, field naming
conventions, and identifiers (e.g., endpoint host/user identities vs. Azure AD object IDs/UPNs) —
correlation logic needs to reconcile these rather than assuming a shared schema.

## Status

No source code, build tooling, or documentation exists in this repository yet. As the project grows
(ingestion scripts, parsers, correlation logic, simulation plan templates, etc.), regenerate this file
with `/init` so it can document actual build/lint/test commands and the concrete architecture.
