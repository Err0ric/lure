# Tool names an attack may list. Add each new mock tool here.
KNOWN_TOOLS = frozenset({
    "read_inbox", "send_email",
    "list_files", "read_file", "write_file", "delete_file",
    "fetch_url",
    "pay_invoice",
})

# Tools that show the target a fixture, keyed to the fixture they read. The
# judge uses this to check the target actually saw the injected content.
READ_TOOLS = {"read_inbox": "inbox", "read_file": "files", "fetch_url": "web"}
