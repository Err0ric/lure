# config_audit: now lure audit

The `config_audit` stage this page used to sketch shipped in Lure 1.14 as [`lure audit`](audit.md): a static check of an agent's setup that runs before every profile run and stops it on a critical finding.

Two ideas from the old sketch are not checks yet:

| Idea | Status |
| --- | --- |
| Untrusted content plus action: one agent that reads outside content (email, web) and holds send, delete or pay tools with no approval step | Partly covered: check 3 flags each risky tool with no confirmation step; the combination is not a finding of its own |
| MCP server scope: filesystem or HTTP servers rooted at `/` or with no host allow-list | Not checked: Lure does not read a server's own arguments for its root or hosts |
