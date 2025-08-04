# NetBBSD – A modern take on traditional Bulletin Board Systems (BBSes)

`NetBBSD` is a retro-inspired, modern-architecture BBS software designed for *nix(-like) systems like NetBSD, FreeBSD, and other POSIX-compatible systems. It brings back the experience of the classic BBS era, enhanced with modern security, Unicode support, an IRC-style real-time chat, and inter-BBS link capabilities.

---

## ✨ Features

- Telnet-based access for real terminal clients
- Support for ANSI art and color menus
- SQLite-backed database with hashed passwords
- Message boards, file areas, and private messages
- Attachment support for message board posts
- Role-based moderation
- Extensive SysOp controls
- Granular permission system
- Real-time chat channels
- Lightweight and dependency-free (Python 3 stdlib only)
- Designed for NetBSD, but should run on or easily be portable to any *nix(-like) system

---

## 📡 Inter-BBS Support

- Easy-to-setup mesh network "NetBBSD Link" between `NetBBSD` BBSes with automatic key exchange
- Inter-BBS PM system
- Linked file areas ("NetBBSD Link Areas") and message boards ("NetBBSD Link Boards")
- Linked IRC-style chat channels ("NetBBSD Link Channels")

---

## 🔐 Security

- Passwords hashed via bcrypt (fallback: pbkdf2_hmac)
- Configurable rate limits for logins
- Idle timeouts to prevent zombie sessions
- No shell evals or arbitrary code execution
- Sandbox to run external programs/door games

---

## 🚀 Getting Started

### Requirements

- Python 3.7+ (3.9+ recommended)
- NetBSD or any UNIX-like system with POSIX support

### Run Locally

```bash
$ python3 netbbsd.py
```

You can connect with:

```bash
$ telnet localhost 2323
```

Upon first run, `netbbsd.py` creates a config file `netbbsd.ini` in the current directory with (hopefully) sensible defaults.
This README is very much work in progress - just like the entire project. Don't expect things to be fully fleshed out or even just working. `NetBBSD` in its current form serves more as a proof of concept, not so much as a turnkey solution (although providing an easy-to-use modern BBS software package is a project goal).

---

## 🛠 Configuration

All configuration takes please in the `netbbsd.ini` INI file. At the very least, you should set a `hostname` for your BBS. 

This documentation is severely lacking, but you might be able to gather more information from the actual code and its annotations. 

---

## 🧩 Future Enhancements

- Compatibility of door game launcher (external process sandbox) with existing door games for other BBS software packages
- Upload/download quotas for file areas
- Attachment support for PMs

---

## 🤝 Contributing

Pull requests and bug reports are welcome. Architecture is deliberately monolithic for ease of deployment, but modularization is possible in future branches (i.e. code is already divided into functions).

---

## 📄 License

This project is licensed under the 3-clause BSD license. See the [LICENSE](LICENSE) file for details.
