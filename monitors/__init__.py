"""RiskRaven Arckon — Protected Files monitoring collectors.

Platform-specific collectors that detect when an AI-related process accesses
a user-designated protected file or directory, or initiates a server access
event (SSH/RDP login). Events are reported to the server via the existing
agent report pipeline.

Modules:
  base.py       — shared process correlation + event formatting
  linux.py      — auditd rules + ausearch parsing
  windows.py    — ETW + Windows Event Log (4663, 4624)
  macos_esf.py  — Endpoint Security framework bridge (Swift helper + socket)
"""