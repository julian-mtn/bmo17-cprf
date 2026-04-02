# bmo17-cprf
Study and implementation of constrained PRFs: construction of BMO17, CJ25 attack, hashed CPRF correction and security analysis

---

### Compile

```bash
make
```

---

### Run

Use the launcher script:

```bash
./start.sh <mode> [parameters]
```

| Mode | Parameters | Description |
|------|------------|------------|
| `-n` | `<size>` | Normal CPRF, number of tests |
| `-h` | `<size>` | Hashed CPRF, number of tests |
| `-l` | `<size>` | Lazy sampling, number of tests |
| `-f` | `<max_tries> <size_N> <size_M>` | FWEAK attack, maximum tries, size N and size M |

---
