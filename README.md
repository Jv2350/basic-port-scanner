# Basic Port Scanner

This project is a beginner-friendly Python port scanner with a simple Tkinter GUI. It demonstrates basic network reconnaissance by checking whether selected TCP ports are open or closed on a target host.

## Features

- Scan common ports like `21`, `22`, `80`, `443`, and `8080`
- Scan a custom range of ports
- Scan a custom comma-separated list of ports
- Display open and closed results in a desktop GUI
- Uses only Python standard library modules: `socket`, `threading`, and `tkinter`

## Run the app

Make sure Python 3 is installed, then run:

```bash
python3 port_scanner_gui.py
```

## How it works

1. Enter a hostname or IP address.
2. Choose whether to scan common ports, a range, or a custom list.
3. Click **Start Scan**.
4. The app uses `socket.connect_ex()` to test each TCP port.
5. Results appear as `OPEN` or `CLOSED`.

## Cybersecurity concept

This project demonstrates **network reconnaissance**, which is the process of gathering information about a target system before deeper security testing. Port scanning helps identify which services may be exposed.

## Important note

Use this tool only on devices, labs, or servers you own or are explicitly allowed to test.
