# Basic Port Scanner

This project now includes two versions of the same idea:

- `port_scanner_gui.py`: a desktop GUI made with Tkinter
- `app.py`: a deployable web app made with Streamlit

Both versions demonstrate basic **network reconnaissance** by checking whether selected TCP ports are open or closed on a target host.

## Features

- Scan common ports like `21`, `22`, `80`, `443`, and `8080`
- Scan a custom range of ports
- Scan a custom comma-separated list of ports
- Show open and closed TCP ports
- Built with Python sockets

## Run locally

### Desktop version

```bash
python3 port_scanner_gui.py
```

### Web version

```bash
pip install -r requirements.txt
streamlit run app.py
```


## Cybersecurity concept

Port scanning is part of network reconnaissance. It helps identify services exposed on a system before deeper security testing begins.
