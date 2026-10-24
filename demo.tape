# Demo GIF for the README. Re-record with: vhs demo.tape
# Needs ANTHROPIC_API_KEY in .env (loaded by lure, never printed) and the
# Opus-judged v1.2.0 Haiku results in results/v1.2.0-2026-10-23/haiku/.
# One live run of lure-tpo-002 (poisoned tool parameter, Haiku failed 3 of 3
# in v1.2.0); the report rates come from the 3-run v1.2.0 results.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 520
Set Padding 20
Set TypingSpeed 25ms
Set Theme "Catppuccin Mocha"

Hide
Type "source .venv/bin/activate && rm -rf results/demo && export PS1='$ ' && clear"
Enter
Show

Type "lure run attacks/tool_poisoning/lure-tpo-002.yaml --target anthropic --model claude-haiku-5-5 --results-dir results/demo"
Enter
Wait+Screen@60s /Saved:/
Sleep 3s

Type "lure report results/v1.2.0-2026-10-23/haiku/ --out reports/haiku-v1.2.0.html"
Enter
Wait+Screen@15s /Wrote reports\/haiku-v1.2.0.html/
Sleep 5s
