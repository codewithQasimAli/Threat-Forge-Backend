---
name: fix-bug
description: Debug and fix issues in ThreatForge. Use when user reports a bug, error, or something not working.
---

# Bug Fix Workflow

1. FIRST read the error message or user description carefully
2. Search for the relevant file using grep or find
3. Read the FULL file before making changes
4. Identify the root cause - do NOT guess
5. If unsure, ask the user to paste the file content
6. Make the MINIMUM change needed to fix the bug
7. After fixing, suggest a verification command the user can run
8. NEVER change unrelated code while fixing a bug
