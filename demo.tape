# Demo GIF for the README. Re-record with: vhs demo.tape
# Needs ANTHROPIC_API_KEY in .env (loaded by lure, never printed) and the
# Opus confirm-run results in results/confirm-opus-2026-10-24/.
# One live run of lure-tpo-002 (poisoned tool parameter) against
# claude-opus-5-5, recorded in one take, whatever it returns. In the
# 2026-10-24 confirm run Opus sent the approval code in 10 of 10 runs of
# this payload. The report comes from that confirm run.

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

Type "lure run attacks/tool_poisoning/lure-tpo-002.yaml --target anthropic --model claude-opus-5-5 --results-dir results/demo"
Enter
Wait+Screen@180s /Saved:/
Sleep 3s

Type "lure report results/confirm-opus-2026-10-24/ --out reports/opus-confirm.html"
Enter
Wait+Screen@15s /Wrote reports\/opus-confirm.html/
Sleep 5s
