# NetBBSD – ANSI-powered BBS for the Terminal Age

`NetBBSD` is a retro-inspired, modern-architecture BBS system designed for minimalist environments like NetBSD, FreeBSD, and other POSIX-compatible systems. It brings back the experience of the classic BBS era, enhanced with modern security, Unicode/ANSI support, and a pluggable architecture ready for real-time chat, door games, and more.

---

## ✨ Features

- Telnet-based access for real terminal clients
- ANSI art, color menus, and retro charm
- SQLite-backed database with hashed passwords
- Message boards, private messages, and wall posts
- Role-based moderation and admin controls
- User idle timeout and login throttling
- Lightweight and dependency-free (Python 3 stdlib only)
- Designed for NetBSD, but portable to any *nix

---

## 🚀 Getting Started

### Requirements

- Python 3.9+
- NetBSD or any UNIX-like system with POSIX support

### Run Locally

```bash
$ python3 netbbsd.py
```

You can connect with:

```bash
$ telnet localhost 6023
```

Upon first run, `netbbsd.py` creates a config file `netbbsd.ini` in the current directory with (hopefully) sensible defaults.
This README is very much work in progress - just like the entire project. Don't expect things to be fully fleshed out or even just working. `NetBBSD` in its current form serves more as a proof of concept, not so much as a turnkey solution (although providing an easy-to-use modern BBS software package is a project goal).

---

## 🔐 Security

- Passwords stored via bcrypt (fallback: pbkdf2_hmac)
- Rate-limited login attempts (configurable)
- Idle disconnects to prevent zombie sessions
- No shell evals or arbitrary code execution
- Optional external door support is sandboxed

---

## 🛠 Configuration

The `[security]` section of `netbbsd.ini` lets you define:

- `max_failed_attempts`
- `block_duration`
- `idle_timeout`

---

## 🧩 Coming Soon

- Door game launcher (external process sandbox)
- File board and upload/download quotas
- Real-time chat between online users
- SSH support for encrypted sessions

---

## 🤝 Contributing

Pull requests welcome and bug reports are welcome. Architecture is deliberately monolithic for ease of deployment, but modularization support is possible in future branches.

---

## 📄 License

This project is licensed under the 3-clause BSD license. See the [LICENSE](LICENSE) file for details.
