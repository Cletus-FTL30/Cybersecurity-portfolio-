# File Integrity Monitoring with Tripwire

**Tripwire** is the original host-based integrity checker and the tool that
defined the category. Its distinguishing feature over AIDE is that the policy,
config and database are **cryptographically signed** with keys you control —
so an attacker who tampers with the baseline files themselves is detected too.
The trade-off is a heavier setup: keys, passphrases, and a compiled policy.

> **Lab:** Cletus-lab (Ubuntu VM, `192.168.0.240`). All work is on a system I own.

---

## Why Tripwire over a script (or AIDE)?

The Python tool stores its baseline as a plain JSON file — anyone who can write
to it can forge a clean result. Tripwire closes that gap: the database is signed
with a **local key** and the policy/config with a **site key**, both protected
by passphrases. The check fails loudly if the baseline itself was altered. This
is the "tamper-evident baseline" model — the same detection as `fim.py`, with
the trust problem solved.

---

## Step 0 — Install (creates keys + passphrases)

```bash
sudo apt update && sudo apt install -y tripwire
```

The Debian postinst walks you through it interactively:

- choose to create **site** and **local** keys,
- set a **site passphrase** (protects the policy/config) and a
  **local passphrase** (protects the database),
- sign the initial config and policy.

Keys land in `/etc/tripwire/site.key` and `/etc/tripwire/<host>-local.key`.

![Tripwire install — generating site and local keys](screenshots/tw-01-install-keys.png)

---

## Step 1 — Point the policy at the watched tree

As with the AIDE guide, I monitor a small test tree mirroring `samples/watched/`:

```bash
sudo mkdir -p /opt/watched && sudo cp -r samples/watched/* /opt/watched/
```

Edit the policy source `/etc/tripwire/twpol.txt` and add a rule. `$(SEC_CRIT)`
is a built-in property mask meaning "any change to contents, size, perms,
inode, owner, etc.":

```text
(
  rulename = "Watched Tree",
  severity = 100
)
{
  /opt/watched    -> $(SEC_CRIT) ;
}
```

Recompile the **signed** policy from the source (prompts for the site
passphrase):

```bash
sudo twadmin --create-polfile -S /etc/tripwire/site.key /etc/tripwire/twpol.txt
```

> A fresh Tripwire policy references many system paths that may not exist on a
> minimal VM, which makes the first check noisy. Trimming `twpol.txt` to the
> paths that actually exist (plus the watched tree) keeps the report focused.

---

## Step 2 — Initialise the database (the baseline)

```bash
sudo tripwire --init
```

This scans every path in the policy, builds the database at
`/var/lib/tripwire/<host>.twd`, and **signs it** with the local key (prompts for
the local passphrase). That signed DB is the trusted baseline.

![Tripwire database initialised](screenshots/tw-02-init.png)

---

## Step 3 — Simulate a compromise

The same four changes as the other demos:

```bash
sudo sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /opt/watched/etc/sshd_config
echo '<?php system($_GET["c"]); ?>' | sudo tee /opt/watched/etc/.shell.php
sudo rm /opt/watched/etc/hosts
sudo chmod 777 /opt/watched/bin/backup.sh
```

---

## Step 4 — Run the integrity check

```bash
sudo tripwire --check
```

Tripwire compares the live tree to the signed database, writes a report to
`/var/lib/tripwire/report/<host>-<date>.twr`, and exits non-zero. The summary
groups violations by rule and severity:

```text
Rule Name           Severity Level    Added    Removed    Modified
---------           --------------    -----    -------    --------
* Watched Tree      100               1        1          2

Total objects scanned:  4
Total violations found: 4
```

Re-print the full report (or read the on-screen one) to see each object and
*which properties* changed:

```bash
sudo twprint --print-report --twrfile /var/lib/tripwire/report/<host>-<date>.twr
```

```text
Added:    "/opt/watched/etc/.shell.php"
Removed:  "/opt/watched/etc/hosts"
Modified: "/opt/watched/etc/sshd_config"   (SHA / size / mtime changed)
Modified: "/opt/watched/bin/backup.sh"     (Mode changed: rw-rw-r-- -> rwxrwxrwx)
```

![Tripwire check report — four violations under the Watched Tree rule](screenshots/tw-03-check-report.png)

The modified-object property matrix is the richest view: it shows a `*` against
exactly which attributes (hash, size, mtime, permissions) moved — directly
analogous to the Python tool distinguishing **Modified** from
**Permissions Changed**.

---

## Step 5 — Approve legitimate changes

After a real, authorised change, fold the current state back into the signed
database from the report (prompts for the local passphrase):

```bash
sudo tripwire --update --twrfile /var/lib/tripwire/report/<host>-<date>.twr
```

To change *what* is monitored, edit `twpol.txt`, then re-sign and reload:

```bash
sudo tripwire --update-policy /etc/tripwire/twpol.txt
```

For ongoing monitoring, `/etc/cron.daily/tripwire` runs the check daily and
mails the report to root.

---

## Findings — Tripwire vs. the Python tool

| Change | `fim.py` | Tripwire |
|--------|----------|----------|
| Contents changed | Modified (Critical) | Modified object, SHA/size property `*` |
| New file | Added (High) | Added object |
| Missing file | Deleted (High) | Removed object |
| Permissions changed | Permissions Changed (Medium) | Modified object, Mode property `*` |
| Baseline trust | plain JSON file | DB signed with the local key (tamper-evident) |
| Clean run exit code | `0` | `0` (non-zero, bit-coded, when violations found) |
