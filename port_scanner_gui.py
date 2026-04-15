"""Basic GUI port scanner built with Tkinter and Python sockets."""

from __future__ import annotations

import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]


class PortScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Basic Port Scanner")
        self.root.geometry("960x680")
        self.root.minsize(840, 620)

        self.status_text = tk.StringVar(value="Ready to scan.")
        self.host_var = tk.StringVar(value="scanme.nmap.org")
        self.mode_var = tk.StringVar(value="common")
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1024")
        self.custom_ports_var = tk.StringVar(value="21, 22, 80, 443")
        self.timeout_var = tk.StringVar(value="0.35")

        self.result_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.scan_thread: threading.Thread | None = None

        self._build_ui()
        self.root.after(120, self._process_queue)

    def _build_ui(self) -> None:
        self.root.configure(bg="#07131f")

        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("TFrame", background="#07131f")
        style.configure("Panel.TFrame", background="#0d1c2b")
        style.configure("TLabel", background="#07131f", foreground="#d7e6f5")
        style.configure("Panel.TLabel", background="#0d1c2b", foreground="#d7e6f5")
        style.configure("Title.TLabel", background="#07131f", foreground="#f4fbff", font=("Avenir Next", 24, "bold"))
        style.configure("Muted.TLabel", background="#07131f", foreground="#8ca6bf")
        style.configure("Status.TLabel", background="#12283b", foreground="#d9f7ff", font=("Menlo", 11))
        style.configure("Action.TButton", font=("Avenir Next", 11, "bold"))
        style.configure("TRadiobutton", background="#0d1c2b", foreground="#d7e6f5")

        container = ttk.Frame(self.root, padding=20)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(2, weight=1)

        header = ttk.Frame(container)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="Basic Port Scanner", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Network reconnaissance demo: test common TCP ports on a host.",
            style="Muted.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))

        controls = ttk.Frame(container, style="Panel.TFrame", padding=18)
        controls.grid(row=1, column=0, sticky="ew")
        for column in range(4):
            controls.columnconfigure(column, weight=1)

        ttk.Label(controls, text="Target host", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        host_entry = tk.Entry(
            controls,
            textvariable=self.host_var,
            bg="#f7fbff",
            fg="#0b1520",
            insertbackground="#0b1520",
            relief="flat",
            font=("Menlo", 12),
        )
        host_entry.grid(row=1, column=0, columnspan=2, sticky="ew", padx=(0, 12), pady=(6, 14), ipady=9)

        ttk.Label(controls, text="Timeout per port (seconds)", style="Panel.TLabel").grid(row=0, column=2, sticky="w")
        timeout_entry = tk.Entry(
            controls,
            textvariable=self.timeout_var,
            bg="#f7fbff",
            fg="#0b1520",
            insertbackground="#0b1520",
            relief="flat",
            font=("Menlo", 12),
        )
        timeout_entry.grid(row=1, column=2, sticky="ew", padx=(0, 12), pady=(6, 14), ipady=9)

        ttk.Label(controls, text="Mode", style="Panel.TLabel").grid(row=0, column=3, sticky="w")
        mode_frame = ttk.Frame(controls, style="Panel.TFrame")
        mode_frame.grid(row=1, column=3, sticky="ew", pady=(6, 14))

        ttk.Radiobutton(mode_frame, text="Common ports", variable=self.mode_var, value="common").pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Range", variable=self.mode_var, value="range").pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Custom list", variable=self.mode_var, value="custom").pack(anchor="w")

        ttk.Label(controls, text="Start port", style="Panel.TLabel").grid(row=2, column=0, sticky="w")
        start_entry = tk.Entry(
            controls,
            textvariable=self.start_port_var,
            bg="#f7fbff",
            fg="#0b1520",
            insertbackground="#0b1520",
            relief="flat",
            font=("Menlo", 12),
        )
        start_entry.grid(row=3, column=0, sticky="ew", padx=(0, 12), pady=(6, 14), ipady=9)

        ttk.Label(controls, text="End port", style="Panel.TLabel").grid(row=2, column=1, sticky="w")
        end_entry = tk.Entry(
            controls,
            textvariable=self.end_port_var,
            bg="#f7fbff",
            fg="#0b1520",
            insertbackground="#0b1520",
            relief="flat",
            font=("Menlo", 12),
        )
        end_entry.grid(row=3, column=1, sticky="ew", padx=(0, 12), pady=(6, 14), ipady=9)

        ttk.Label(controls, text="Custom ports", style="Panel.TLabel").grid(row=2, column=2, columnspan=2, sticky="w")
        custom_entry = tk.Entry(
            controls,
            textvariable=self.custom_ports_var,
            bg="#f7fbff",
            fg="#0b1520",
            insertbackground="#0b1520",
            relief="flat",
            font=("Menlo", 12),
        )
        custom_entry.grid(row=3, column=2, columnspan=2, sticky="ew", pady=(6, 14), ipady=9)

        action_row = ttk.Frame(controls, style="Panel.TFrame")
        action_row.grid(row=4, column=0, columnspan=4, sticky="ew")
        action_row.columnconfigure(2, weight=1)

        scan_button = ttk.Button(action_row, text="Start Scan", style="Action.TButton", command=self.start_scan)
        scan_button.grid(row=0, column=0, sticky="w")

        clear_button = ttk.Button(action_row, text="Clear Results", command=self.clear_results)
        clear_button.grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Label(
            action_row,
            text="Use only on systems you own or have permission to test.",
            style="Panel.TLabel",
        ).grid(row=0, column=2, sticky="e")

        results_panel = ttk.Frame(container, style="Panel.TFrame", padding=18)
        results_panel.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        results_panel.columnconfigure(0, weight=1)
        results_panel.rowconfigure(1, weight=1)

        ttk.Label(results_panel, text="Scan Results", style="Panel.TLabel", font=("Avenir Next", 16, "bold")).grid(
            row=0, column=0, sticky="w"
        )

        self.results = ScrolledText(
            results_panel,
            wrap="word",
            font=("Menlo", 15, "bold"),
            bg="#08111a",
            fg="#d7f4ff",
            insertbackground="#d7f4ff",
            relief="flat",
            padx=12,
            pady=12,
        )
        self.results.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        self.results.tag_configure("open", foreground="#67f7b2")
        self.results.tag_configure("closed", foreground="#f7a668")
        self.results.tag_configure("header", foreground="#7fd1ff")
        self.results.tag_configure("summary", foreground="#fff2a8")
        self.results.insert("end", "Choose a host and click Start Scan.\n", "header")
        self.results.configure(state="disabled")

        status_bar = ttk.Label(
            container,
            textvariable=self.status_text,
            style="Status.TLabel",
            anchor="w",
            padding=(14, 10),
        )
        status_bar.grid(row=3, column=0, sticky="ew", pady=(14, 0))

        host_entry.focus_set()

    def clear_results(self) -> None:
        self._set_results("")
        self.status_text.set("Results cleared.")

    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan in progress", "Please wait for the current scan to finish.")
            return

        host = self.host_var.get().strip()
        if not host:
            messagebox.showerror("Missing host", "Enter a hostname or IP address.")
            return

        try:
            timeout = float(self.timeout_var.get().strip())
            if timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid timeout", "Timeout must be a positive number such as 0.35.")
            return

        try:
            ports = self._get_ports_for_mode()
        except ValueError as error:
            messagebox.showerror("Invalid ports", str(error))
            return

        self._set_results("")
        self._append_result(f"Scanning {host} on {len(ports)} port(s)...\n", "header")
        self.status_text.set(f"Resolving host {host}...")

        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(host, ports, timeout),
            daemon=True,
        )
        self.scan_thread.start()

    def _get_ports_for_mode(self) -> list[int]:
        mode = self.mode_var.get()
        if mode == "common":
            return COMMON_PORTS

        if mode == "range":
            try:
                start = int(self.start_port_var.get().strip())
                end = int(self.end_port_var.get().strip())
            except ValueError as error:
                raise ValueError("Start and end ports must be whole numbers.") from error

            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError("Ports must be between 1 and 65535.")
            if start > end:
                raise ValueError("Start port must be less than or equal to end port.")
            if end - start > 2048:
                raise ValueError("Please keep range scans to 2048 ports or fewer for this basic tool.")
            return list(range(start, end + 1))

        raw_ports = [item.strip() for item in self.custom_ports_var.get().split(",")]
        if not raw_ports or raw_ports == [""]:
            raise ValueError("Enter a comma-separated list like 21, 22, 80.")

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
            raise ValueError("Provide at least one valid port.")

        return sorted(set(ports))

    def _run_scan(self, host: str, ports: list[int], timeout: float) -> None:
        started_at = time.perf_counter()
        try:
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            self.result_queue.put(("error", f"Could not resolve host: {host}"))
            return

        self.result_queue.put(("status", f"Scanning {host} ({ip_address})..."))

        open_ports: list[int] = []
        for index, port in enumerate(ports, start=1):
            is_open, service_name = self._scan_port(ip_address, port, timeout)
            if is_open:
                open_ports.append(port)
                self.result_queue.put(("result", ("open", port, service_name)))
            else:
                self.result_queue.put(("result", ("closed", port, service_name)))

            self.result_queue.put(("progress", (index, len(ports), host)))

        elapsed = time.perf_counter() - started_at
        self.result_queue.put(("done", (host, ip_address, open_ports, elapsed, len(ports))))

    def _scan_port(self, ip_address: str, port: int, timeout: float) -> tuple[bool, str]:
        service_name = self._lookup_service_name(port)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            result = connection.connect_ex((ip_address, port))

        return result == 0, service_name

    @staticmethod
    def _lookup_service_name(port: int) -> str:
        try:
            return socket.getservbyport(port)
        except OSError:
            return "unknown"

    def _process_queue(self) -> None:
        try:
            while True:
                event, payload = self.result_queue.get_nowait()
                if event == "status":
                    self.status_text.set(str(payload))
                elif event == "error":
                    self.status_text.set("Scan failed.")
                    messagebox.showerror("Scan error", str(payload))
                elif event == "result":
                    state, port, service_name = payload
                    label = f"Port {port:<5} {service_name:<10} {state.upper()}\n"
                    self._append_result(label, state)
                elif event == "progress":
                    current, total, host = payload
                    self.status_text.set(f"Scanning {host}: {current}/{total} ports checked.")
                elif event == "done":
                    host, ip_address, open_ports, elapsed, total_ports = payload
                    if open_ports:
                        summary = f"\nOpen ports on {host} ({ip_address}): {', '.join(map(str, open_ports))}\n"
                    else:
                        summary = f"\nNo open ports found on {host} ({ip_address}) in the selected set.\n"
                    summary += f"Completed in {elapsed:.2f} seconds across {total_ports} port(s).\n"
                    self._append_result(summary, "summary")
                    self.status_text.set("Scan complete.")
        except queue.Empty:
            pass
        finally:
            self.root.after(120, self._process_queue)

    def _set_results(self, content: str) -> None:
        self.results.configure(state="normal")
        self.results.delete("1.0", "end")
        if content:
            self.results.insert("end", content)
        self.results.configure(state="disabled")

    def _append_result(self, text: str, tag: str | None = None) -> None:
        self.results.configure(state="normal")
        self.results.insert("end", text, tag)
        self.results.see("end")
        self.results.configure(state="disabled")


def main() -> None:
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
