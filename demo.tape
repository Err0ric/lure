# Demo GIF for the README. Re-record with: vhs demo.tape
# Needs ANTHROPIC_API_KEY in .env (loaded by lure, never printed) and the
# Opus-judged Haiku baseline in results/baseline-2026-10-23/rescored-opus/.
# One live run; the report rates come from the 3-run baseline.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 720
Set Padding 20
Set TypingSpeed 25ms
Set Theme "Catppuccin Mocha"

Hide
Type "source .venv/bin/activate && rm -rf results/demo && export PS1='$ ' && clear"
Enter
Show

Type "lure run attacks/jailbreak/lure-jbk-002-v1.yaml --target anthropic --model claude-haiku-5-5 --results-dir results/demo"
Enter
Wait+Screen@60s /Saved:/
Sleep 3s

Type "lure report results/baseline-2026-10-23/rescored-opus/ --out reports/haiku-baseline.html"
Enter
Wait+Screen@15s /v1: \d+ of \d+ runs/
Sleep 5s
