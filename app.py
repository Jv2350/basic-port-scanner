"""Deployable Streamlit port scanner demo."""

from __future__ import annotations

import socket
import time

import pandas as pd
import streamlit as st


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]


def parse_ports(mode: str, start_port: int, end_port: int, custom_ports: str) -> list[int]:
    if mode == "Common ports":
        return COMMON_PORTS

    if mode == "Range":
        if start_port > end_port:
            raise ValueError("Start port must be less than or equal to end port.")
        if end_port - start_port > 2048:
            raise ValueError("Please keep range scans to 2048 ports or fewer.")
        return list(range(start_port, end_port + 1))

    raw_ports = [item.strip() for item in custom_ports.split(",")]
    ports: list[int] = []

    for item in raw_ports:
        if not item:
            continue
        try:
            port = int(item)
        except ValueError as error:
            raise ValueError(f"'{item}' is not a valid port number.") from error

        if not 1 <= port <= 65535:
            raise ValueError("Ports must be between 1 and 65535.")

        ports.append(port)

    if not ports:
        raise ValueError("Enter at least one valid custom port.")

    return sorted(set(ports))


def lookup_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def scan_port(ip_address: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        return connection.connect_ex((ip_address, port)) == 0


def main() -> None:
    st.set_page_config(
        page_title="Basic Port Scanner",
        page_icon="🛰️",
        layout="wide",
    )

    st.title("Basic Port Scanner")
    st.caption("A small web-based network reconnaissance demo built with Python, Streamlit, and sockets.")

    st.warning(
        "Use this only on hosts you own or have explicit permission to test. "
        "Some cloud hosts may block or limit scanning behavior."
    )

    with st.sidebar:
        st.header("Scan Settings")
        host = st.text_input("Hostname or IP address", value="scanme.nmap.org")
        mode = st.radio("Port selection", ["Common ports", "Range", "Custom list"])
        start_port = st.number_input("Start port", min_value=1, max_value=65535, value=1)
        end_port = st.number_input("End port", min_value=1, max_value=65535, value=1024)
        custom_ports = st.text_input("Custom ports", value="21, 22, 80, 443")
        timeout = st.slider("Timeout per port (seconds)", min_value=0.1, max_value=2.0, value=0.35, step=0.05)
        run_scan = st.button("Start Scan", type="primary", use_container_width=True)

    left, right = st.columns([1.2, 1])

    with left:
        st.subheader("What it does")
        st.write(
            "This tool checks whether selected TCP ports are open or closed by trying to connect "
            "to them with Python's `socket.connect_ex()`."
        )
        st.code(
            "Example targets: localhost, 127.0.0.1, scanme.nmap.org",
            language="text",
        )

    with right:
        st.subheader("Cybersecurity concept")
        st.write(
            "Port scanning is part of network reconnaissance. It helps identify services that may "
            "be exposed on a host before deeper security testing."
        )

    if not run_scan:
        st.info("Choose a target and click Start Scan.")
        return

    if not host.strip():
        st.error("Enter a hostname or IP address.")
        return

    try:
        ports = parse_ports(mode, int(start_port), int(end_port), custom_ports)
    except ValueError as error:
        st.error(str(error))
        return

    try:
        ip_address = socket.gethostbyname(host.strip())
    except socket.gaierror:
        st.error(f"Could not resolve host: {host}")
        return

    st.success(f"Resolved `{host}` to `{ip_address}`. Starting scan on {len(ports)} port(s).")

    progress = st.progress(0)
    status = st.empty()
    started_at = time.perf_counter()
    rows: list[dict[str, str | int]] = []

    for index, port in enumerate(ports, start=1):
        is_open = scan_port(ip_address, port, timeout)
        rows.append(
            {
                "Port": port,
                "Service": lookup_service_name(port),
                "Status": "OPEN" if is_open else "CLOSED",
            }
        )
        progress.progress(index / len(ports))
        status.write(f"Scanning `{host}`: {index}/{len(ports)} ports checked")

    elapsed = time.perf_counter() - started_at
    results = pd.DataFrame(rows)
    open_results = results[results["Status"] == "OPEN"]

    metric_one, metric_two, metric_three = st.columns(3)
    metric_one.metric("Target", host)
    metric_two.metric("Ports checked", len(ports))
    metric_three.metric("Open ports", len(open_results))

    st.subheader("Results")
    st.dataframe(results, use_container_width=True, hide_index=True)

    if open_results.empty:
        st.info(f"No open ports were found in the selected set. Scan completed in {elapsed:.2f} seconds.")
    else:
        st.success(
            f"Open ports found: {', '.join(str(port) for port in open_results['Port'].tolist())}. "
            f"Scan completed in {elapsed:.2f} seconds."
        )


if __name__ == "__main__":
    main()
