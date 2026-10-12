# Snake CPU wordlists

Generated locally. Do not commit the `.txt` files.

| File | Use |
| --- | --- |
| `snake-target.txt` | Per-job ESSID mutations (rewritten each crack). |
| `snake-fast.txt` | First catalog pass. Ranked WPA-probable keys. |
| `snake-smart.txt` | Default. Fast plus 100k leaks and keyboard walks. |
| `snake-deep.txt` | Last local pass. WPA-filtered rockyou. Slow on CPU. |

```bash
python3 snake.py wordlists --rebuild
python3 snake.py wordlists --use smart
```

Sources: SecLists (`WiFi-WPA`, `Common-Credentials`, `Keyboard-Walks`) and
`/home/kali/wordlists/rockyou.txt` when present. Entries shorter than 8
characters are dropped because they cannot be WPA-PSK keys.

hashcat Fast/Smart jobs also apply `best66.rule` so you get mutations without
storing a second giant file.
