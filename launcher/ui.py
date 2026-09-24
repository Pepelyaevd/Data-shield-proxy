#!/usr/bin/env python3
"""Managed Launcher — минимальный UI-клиент (Tkinter, без внешних зависимостей).

Кнопка «Открыть Claude (под защитой)» запускает агента через корпоративный прокси:
UI — тонкая надстройка над launcher/launch.py (та же логика: прокси только этому
процессу + доверие к CA + идентичность). Настройки берутся из .dsp.env (провижининг
один раз) и правятся в полях. В целевой картине identity здесь заменит SSO/mTLS
вместо секрета-ворот.

Запуск:  python3 launcher/ui.py   (или: make ui)
"""

from __future__ import annotations

import getpass
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import tkinter as tk  # noqa: E402
from tkinter import ttk  # noqa: E402

from launcher.launch import (  # noqa: E402
    DEFAULT_CA,
    DEFAULT_NO_PROXY,
    DEFAULT_PROXY,
    DEFAULT_SECRET,
    build_command,
    build_environment,
    load_profiles,
    _hostport,
    _proxy_with_identity,
)

PLANTED_SECRET = "AKIAIOSFODNN7EXAMPLE"  # синтетический AWS-ключ для проверки перехвата


def _build_subs(user, agent, proxy, secret, ca, no_proxy):
    return {
        "proxy_url": _proxy_with_identity(proxy, user, secret),
        "proxy_hostport": _hostport(proxy),
        "ca_path": ca,
        "no_proxy": no_proxy,
        "user": user,
        "agent": agent,
        "device": platform.node(),
    }


def _overrides(profile, subs):
    """Только внедряемые переменные (для скрипта, открываемого в терминале)."""
    ov = {k: v.format(**subs) for k, v in profile.get("env", {}).items()}
    ov["DSP_USER"] = subs["user"]
    ov["DSP_AGENT"] = subs["agent"]
    return ov


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Data-Shield-Proxy — Managed Launcher")
        root.geometry("560x520")
        self.profiles = load_profiles()

        pad = {"padx": 10, "pady": 4}

        banner = tk.Label(
            root,
            text="🛡  Трафик запускаемого агента идёт через корпоративный прокси\n"
                 "и инспектируется согласно политике мониторинга.",
            bg="#0b5", fg="white", font=("Helvetica", 12, "bold"),
            justify="center", pady=10,
        )
        banner.pack(fill="x")

        form = ttk.Frame(root)
        form.pack(fill="x", **pad)

        self.user = tk.StringVar(value=getpass.getuser())
        self.agent = tk.StringVar(value="claude-code")
        self.proxy = tk.StringVar(value=DEFAULT_PROXY)
        self.secret = tk.StringVar(value=DEFAULT_SECRET)
        self.ca = tk.StringVar(value=DEFAULT_CA)

        self._row(form, "Пользователь", self.user, 0)
        self._row(form, "Агент", self.agent, 1)
        self._row(form, "Прокси", self.proxy, 2)
        self._row(form, "Секрет", self.secret, 3, show="•")
        self._row(form, "CA (PEM)", self.ca, 4)

        self.ca_status = tk.Label(root, text="", anchor="w", fg="#555")
        self.ca_status.pack(fill="x", padx=12)
        self._refresh_ca_status()
        self.ca.trace_add("write", lambda *_: self._refresh_ca_status())

        btns = ttk.Frame(root)
        btns.pack(fill="x", **pad)
        ttk.Button(btns, text="▶  Открыть Claude (под защитой)",
                   command=self.open_agent).pack(side="left", padx=4)
        ttk.Button(btns, text="✓  Проверить перехват (тест-секрет)",
                   command=self.check_intercept).pack(side="left", padx=4)

        tk.Label(root, text="Журнал:", anchor="w").pack(fill="x", padx=12)
        self.log = tk.Text(root, height=12, wrap="word", bg="#111", fg="#ddd",
                           font=("Menlo", 10))
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._log(f"Готово. Прокси: {self.proxy.get()} · пользователь: {self.user.get()}")

    def _row(self, parent, label, var, r, show=None):
        ttk.Label(parent, text=label, width=14).grid(row=r, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=var, width=48, show=show).grid(
            row=r, column=1, sticky="we", pady=3)
        parent.columnconfigure(1, weight=1)

    def _refresh_ca_status(self):
        path = os.path.expanduser(self.ca.get())
        if os.path.isfile(path):
            self.ca_status.config(text=f"CA найден: {path}", fg="#0a7")
        else:
            self.ca_status.config(text=f"CA НЕ найден: {path} — TLS-инспекция не будет "
                                       "доверенной", fg="#c33")

    def _log(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.root.update_idletasks()

    def _profile(self):
        return self.profiles["cli"]

    def _subs(self):
        return _build_subs(self.user.get().strip() or getpass.getuser(),
                           self.agent.get().strip() or "generic",
                           self.proxy.get().strip(), self.secret.get(),
                           os.path.expanduser(self.ca.get().strip()), DEFAULT_NO_PROXY)

    # --- действия ------------------------------------------------------- #

    def open_agent(self):
        """Открывает агент (claude) в терминале с внедрёнными параметрами прокси."""
        subs = self._subs()
        overrides = _overrides(self._profile(), subs)
        run_cmd = ["claude"]
        if not shutil.which("claude"):
            self._log("⚠ 'claude' не найден в PATH. Установи Claude Code или измени поле «Агент».")
            return
        try:
            path = self._write_launch_script(overrides, run_cmd)
            self._open_terminal(path)
            self._log(f"▶ Открываю Claude под защитой (user={subs['user']}). "
                      "Пиши запросы в открывшемся терминале.")
        except Exception as e:
            self._log(f"Ошибка запуска: {e}")

    def check_intercept(self):
        """Шлёт тестовый запрос с посаженным секретом через прокси (curl), показывает ответ."""
        subs = self._subs()
        env = build_environment(self._profile(), subs)
        body = ('{"model":"claude-sonnet-5","max_tokens":16,"messages":'
                '[{"role":"user","content":"DLP test key %s"}]}' % PLANTED_SECRET)
        cmd = ["curl", "-sS", "--max-time", "25",
               "https://api.anthropic.com/v1/messages",
               "-H", "content-type: application/json",
               "-H", "anthropic-version: 2023-06-01",
               "-d", body]
        self._log(f"✓ Отправляю тест-секрет через прокси как user={subs['user']} …")

        def worker():
            try:
                p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
                out = (p.stdout or p.stderr).strip()
                self._log("Ответ: " + (out[:400] if out else "(пусто)"))
                self._log("→ Если получен ответ от api.anthropic.com — перехват сработал; "
                          "инцидент появится в отчёте на сервере (сигнатура aws_access_key).")
            except Exception as e:
                self._log(f"Ошибка проверки: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # --- запуск терминала ---------------------------------------------- #

    def _write_launch_script(self, overrides, run_cmd):
        lines = ["#!/bin/bash", "clear",
                 'echo "[Data-Shield-Proxy] Трафик агента под корпоративным мониторингом."',
                 'echo']
        for k, v in overrides.items():
            lines.append(f"export {k}={shlex.quote(v)}")
        lines.append("exec " + " ".join(shlex.quote(c) for c in run_cmd))
        fd, path = tempfile.mkstemp(suffix=".command", prefix="dsp-launch-")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(path, 0o755)
        return path

    def _open_terminal(self, path):
        system = platform.system()
        if system == "Darwin":
            subprocess.run(["open", path], check=False)
        elif system == "Linux":
            for term in (["x-terminal-emulator", "-e"], ["gnome-terminal", "--"],
                         ["konsole", "-e"], ["xterm", "-e"]):
                if shutil.which(term[0]):
                    subprocess.Popen(term + ["bash", path])
                    return
            self._log(f"Терминал не найден. Запусти вручную: {path}")
        else:
            self._log(f"Запусти вручную: {path}")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
