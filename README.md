# Airlock

[![CI](https://github.com/Robomba/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/Robomba/airlock/actions/workflows/ci.yml)
&nbsp;·&nbsp; MIT &nbsp;·&nbsp; zero runtime deps &nbsp;·&nbsp; runs entirely on your machine

### Stop watching your agent.

You don't babysit your coding agent because it's dangerous. You babysit it because you can't tell the difference between it *reading a file* and it *reading your `.env` and POSTing it to an IP it found in a README.*

Airlock can. So you can go do something else.

```bash
pip install airlock-agent
airlock report
```

> The PyPI package is **`airlock-agent`** (plain `airlock` is an unrelated project); the
> command is just `airlock`. For the bleeding edge:
> `pip install "git+https://github.com/Robomba/airlock.git"`.

No config. It reads the logs your agent already wrote and tells you what it's been doing.

```
  This session — 8 agent actions:

     1  file reads touched credentials  (/home/dev/app/.env)
     3  network calls to 3 domains  (docs.example.com, collect.evil.example, api.github.com)
     1  destructive commands                (no confirmation asked)
     1  outbound payload carried a secret read earlier   <- this is the one
     2  action(s) taken shortly after reading untrusted content
```

**Free. MIT. Runs entirely on your machine. Makes zero network calls of its own.**

---

## Why it's different

Every other guardrail matches **keywords**. We published the benchmark showing that doesn't work: a bag-of-words classifier with no model at all scores **0.967** on the standard harm benchmark — and **0.493 (chance)** the moment the attacker stops using the obvious words. Keyword guardrails aren't detecting intent. They're detecting vocabulary. ([AICES paper](https://github.com/Robomba/ai-control-eval-suite) · [dataset](https://huggingface.co/datasets/Robomb/aices-minpair-control))

Airlock watches **where data came from and where it's going.** It tracks which tool results are untrusted (web/email/file/MCP), taints the session when the agent reads them, and fingerprints every secret it sees so it can spot that secret leaving the machine — **even base64-encoded.** *"The agent read `evil.com`, then tried to POST your `.env`"* is not a wording problem. You can't rephrase your way past a hash comparison.

---

## Turn it on (live gating)

Airlock plugs into Claude Code as two hooks. **You need both.**

```jsonc
// ~/.claude/settings.json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command", "command": "airlock hook"  }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "airlock watch" }] }]
  }
}
```

Why two? `PreToolUse` fires *before* a tool runs, so it never sees a **result** —
no result, no secret bytes, nothing to fingerprint. `airlock watch` (PostToolUse)
is the only place a secret can actually be captured. **Without `watch`, Airlock
can only judge one action at a time and cross-call exfiltration is not detected.**
With it, "read the `.env` at step 3, POST it to an unknown host at step 19" is
caught — the payload at step 19 looks innocent on its own.

### Modes

| Mode | Behaviour | Use it when |
|---|---|---|
| `observe` | Scores and logs everything, **always allows**. Cannot stall an agent. | You're building trust, or the agent runs unattended and must never block. |
| `enforce` *(default)* | A hard-stop surfaces to you as an **ask**. Everything else auto-approves. | You're at the keyboard. |
| `enforce --headless` | A hard-stop **denies** instead of asking. | Nobody is there — an "ask" nobody answers is a hang, not a guardrail. |

Set with `--mode`, or `$AIRLOCK_MODE`, or a `~/.airlock-mode` file.

**Kill switch:** `echo observe > ~/.airlock-mode` — instantly back to logging-only,
no restart, no config edit.

### What it never does

Airlock **never writes your secrets to disk.** Session state holds only rolling-hash
fingerprints and salted hashes — enough to recognise those bytes trying to leave,
not enough to reconstruct them. A stolen state file yields nothing. (State lives in
`~/.cache/airlock/sessions`, mode `0600`, expires after 7 days.)

It also **fails open, on purpose**: if Airlock itself errors, the tool call is
allowed and the error is logged. A broken guardrail must never brick the agent it
is watching. That is a deliberate trade-off, and it is the honest one to state:
**Airlock is a safety net, not a guarantee.** It can miss things. Do not use it as
the only thing standing between an agent and something you cannot undo.

## Our promises

These are commitments, not features. They're the reason you can trust a security tool you didn't write.

**1. We will never phone home.** Zero telemetry, zero analytics, no network calls of Airlock's own — ever. A security tool that exfiltrates your data to prove nothing is exfiltrating your data is a joke. The code is MIT; verify it.

**2. We publish our false-alarm rate every release.** Not our catch rate — anyone can catch everything by blocking everything. The number that matters is **how often we interrupt you for nothing**, and we print it whether it's good or bad. No other guardrail publishes this. Ask them why.

**3. Sixty seconds or we failed.** Install to first insight with no config file, no policy language, no account. If you have to *learn* Airlock before it helps you, we built it wrong.

**4. Some things always stop for a human.** Money moving, production, anything irreversible — those wake you up no matter what your policy says. No "trust level" will ever override that. If a tool offers to fully automate spending your money, close the tab.

**5. We tell you what we can't do.** (See below — it stays in the README, permanently.)

**6. We'll never ship an attack to sell the defense.** Our demos use dummy canaries and local sinks. We don't publish weapons.

**7. Free, MIT, forever.** And the benchmark we grade ourselves with is public — run it against us, and against everyone else.

---


## ⚠ Disclaimer

**Airlock is best-effort and will make mistakes.** It can miss real attacks and flag safe
actions. It is **not a guarantee of safety**, not a substitute for code review or OS
sandboxing, and is provided **AS IS with no warranty** (MIT). Benchmark numbers come from a
small, non-human-audited seed set and are indicative, not definitive. **You are responsible
for what your agent does.** Full text: [DISCLAIMER.md](DISCLAIMER.md).

## What Airlock does NOT catch

A security tool that overclaims is worse than none. Airlock sees **actions, not thoughts.**

- **A genuinely malicious model with a covert channel.** If the model is the adversary and hides intent in benign-looking actions, Airlock can't read its mind.
- **Anything outside the tool-call boundary.** If it doesn't go through a tool call Airlock can see, Airlock can't see it.
- **Closed chat UIs** (ChatGPT / Claude web). There's no interception point.
- **It is not a substitute for OS-level sandboxing.** Run untrusted agents in a container/VM. Airlock is a layer on top, not a replacement.

Airlock **reduces babysitting; it does not eliminate risk.**

---

## Status

**Shipped (local, verified):**
- `airlock report` — read-only, zero-config: what your agent has been doing.
- `airlock digest` — the session receipt: what was let through and *why it was safe*.
- `airlock learn` — writes an editable allow-policy from your own sessions (opt-in tuning).
- `airlock run` — unattended supervision: **auto-approve in-policy, hard-stop the irreversible.** Money, production, destructive, sign-in, install, and any secret leaving the machine always stop for a human — no policy can override that.
- `airlock hook` — the live Claude Code PreToolUse gate (returns allow / ask per tool call).

**Next:** `airlock eval` — the public precision benchmark (false alarms per 1,000 actions).


## License

MIT. Local-first. No network calls of its own.
