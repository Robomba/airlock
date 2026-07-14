# Airlock — Disclaimer & Limitations

**Airlock is best-effort software. It WILL make mistakes.**

- It can **miss real attacks** (false negatives). A quiet report is not proof you are safe.
- It can **flag safe actions** (false positives).
- It is **NOT a guarantee** of safety and **NOT a substitute** for code review, human judgment, or OS-level sandboxing. Run untrusted agents in a VM or container.
- It sees **actions, not intent**. It cannot stop a genuinely malicious model with a covert channel, and it cannot see inside closed chat UIs.
- Benchmark numbers (`airlock eval`) come from a **small, non-human-audited seed set** and are **indicative, not definitive**.

**No warranty.** Airlock is provided "AS IS", without warranty of any kind, express or implied, including merchantability, fitness for a particular purpose, and non-infringement (see LICENSE / MIT). In no event shall the authors be liable for any claim, damages, or other liability arising from the use of this software.

**You are responsible for what your agent does.** Airlock is a safety *aid*, not a safety *guarantee*. Use it as one layer of defense, not the only one.
