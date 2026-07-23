"""Stopgate — stop watching your agent.

A local-first safety envelope for coding agents. Detection is by PROVENANCE and
DATAFLOW, never keywords: every tool result is tagged trusted/untrusted, an
untrusted read taints the session, high-risk actions near untrusted content
escalate, and outbound bytes are matched (by rolling hash) against secrets read
earlier in the session.

Stopgate makes zero network calls of its own. Standard library only.
"""

__version__ = "0.1.0"
