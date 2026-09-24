#!/usr/bin/env python3
"""Managed Launcher — локальный веб-UI (stdlib http.server, без зависимостей).

Надёжная альтернатива Tkinter (который на системном Tk 8.5/macOS рисует пусто):
поднимает локальный сервер на 127.0.0.1, открывает страницу в браузере с кнопкой
«Открыть Claude (под защитой)». Логика запуска — та же, что в launch.py.

Запуск:  python3 launcher/webui.py   (или: make webui)
Остановка: Ctrl+C.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from launcher.launch import (  # noqa: E402
    DEFAULT_CA,
    DEFAULT_NO_PROXY,
    DEFAULT_PROXY,
    DEFAULT_SECRET,
    build_environment,
    load_profiles,
    _hostport,
    _proxy_with_identity,
)

PLANTED_SECRET = "AKIAIOSFODNN7EXAMPLE"
_PROFILES = load_profiles()


# --------------------------------------------------------------------------- #
# Логика запуска (общая с launch.py по смыслу)
# --------------------------------------------------------------------------- #

def _subs(user, agent, proxy, secret, ca):
    return {
        "proxy_url": _proxy_with_identity(proxy, user, secret),
        "proxy_hostport": _hostport(proxy),
        "ca_path": os.path.expanduser(ca),
        "no_proxy": DEFAULT_NO_PROXY,
        "user": user,
        "agent": agent,
        "device": platform.node(),
    }


def _overrides(subs):
    prof = _PROFILES["cli"]
    ov = {k: v.format(**subs) for k, v in prof.get("env", {}).items()}
    ov["DSP_USER"] = subs["user"]
    ov["DSP_AGENT"] = subs["agent"]
    return ov


def _resolve_binary(name):
    """Находит абсолютный путь к исполняемому файлу агента.

    Серверный процесс UI может быть запущен не из login-shell (нет ~/.local/bin
    в PATH), да и открываемый терминал не всегда его видит — поэтому ищем явно
    и вписываем абсолютный путь в скрипт запуска.
    """
    p = shutil.which(name)
    if p:
        return p
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".local", "bin", name),
        os.path.join(home, ".claude", "local", name),
        os.path.join(home, "bin", name),
        f"/opt/homebrew/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    shell = os.environ.get("SHELL", "/bin/zsh")
    try:
        out = subprocess.run([shell, "-lic", f"command -v {shlex.quote(name)}"],
                             capture_output=True, text=True, timeout=8).stdout.strip()
        if out and os.path.isfile(out.splitlines()[-1]):
            return out.splitlines()[-1]
    except Exception:
        pass
    return None


def _write_script(subs, run_cmd):
    lines = ["#!/bin/bash", "clear",
             'echo "[Data-Shield-Proxy] Трафик агента под корпоративным мониторингом."',
             "echo"]
    for k, v in _overrides(subs).items():
        lines.append(f"export {k}={shlex.quote(v)}")
    lines.append("exec " + " ".join(shlex.quote(c) for c in run_cmd))
    fd, path = tempfile.mkstemp(suffix=".command", prefix="dsp-launch-")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o755)
    return path


def _open_terminal(path):
    system = platform.system()
    if system == "Darwin":
        subprocess.run(["open", path], check=False)
        return "Открыт терминал с Claude под защитой."
    if system == "Linux":
        for term in (["x-terminal-emulator", "-e"], ["gnome-terminal", "--"],
                     ["konsole", "-e"], ["xterm", "-e"]):
            if shutil.which(term[0]):
                subprocess.Popen(term + ["bash", path])
                return "Открыт терминал с Claude под защитой."
        return f"Терминал не найден. Запусти вручную: {path}"
    return f"Запусти вручную: {path}"


def _run_check(subs):
    env = build_environment(_PROFILES["cli"], subs)
    body = ('{"model":"claude-sonnet-5","max_tokens":16,"messages":'
            '[{"role":"user","content":"DLP test key %s"}]}' % PLANTED_SECRET)
    cmd = ["curl", "-sS", "--max-time", "25",
           "https://api.anthropic.com/v1/messages",
           "-H", "content-type: application/json",
           "-H", "anthropic-version: 2023-06-01", "-d", body]
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
        return (p.stdout or p.stderr).strip()[:600] or "(пустой ответ)"
    except Exception as e:
        return f"Ошибка: {e}"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Data-Shield-Proxy — Launcher</title>
<style>
 :root{color-scheme:light dark}
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:0 auto;padding:20px;background:#f6f7f9;color:#1a1a1a}
 @media(prefers-color-scheme:dark){body{background:#14161a;color:#e6e6e6}input{background:#1c1f24;color:#eee;border-color:#333}}
 .banner{background:#0b8a4b;color:#fff;padding:12px 16px;border-radius:10px;font-weight:600;text-align:center;margin-bottom:18px}
 label{display:block;font-size:13px;color:#888;margin:10px 0 3px}
 input{width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid #ccc;border-radius:8px;font-size:14px}
 .row{display:flex;gap:10px}.row>div{flex:1}
 button{margin-top:16px;margin-right:8px;padding:11px 16px;border:0;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
 .primary{background:#2563eb;color:#fff}.ghost{background:#e3e6ea;color:#222}
 #log{margin-top:18px;background:#111;color:#ddd;border-radius:8px;padding:12px;font-family:Menlo,monospace;font-size:12px;white-space:pre-wrap;min-height:120px}
 .ok{color:#12b886}.err{color:#ff6b6b}
</style></head><body>
<div class="banner">🛡 Трафик запускаемого агента идёт через корпоративный прокси и инспектируется</div>
<div class="row"><div><label>Пользователь</label><input id="user" value="__USER__"></div>
<div><label>Агент</label><input id="agent" value="claude-code"></div></div>
<label>Прокси</label><input id="proxy" value="__PROXY__">
<div class="row"><div><label>Секрет</label><input id="secret" type="password" value="__SECRET__"></div>
<div><label>CA (PEM)</label><input id="ca" value="__CA__"></div></div>
<button class="primary" onclick="act('open')">▶ Открыть Claude (под защитой)</button>
<button class="ghost" onclick="act('check')">✓ Проверить перехват</button>
<div id="log">Готово. Прокси: __PROXY__</div>
<script>
 function fields(){return {user:user.value,agent:agent.value,proxy:proxy.value,secret:secret.value,ca:ca.value};}
 function log(m,c){const d=document.getElementById('log');d.innerHTML+='\\n'+(c?'<span class="'+c+'">'+m+'</span>':m);d.scrollTop=d.scrollHeight;}
 async function act(kind){
   log(kind==='open'?'Запускаю Claude…':'Отправляю тест-секрет…');
   try{const r=await fetch('/'+kind,{method:'POST',body:JSON.stringify(fields())});
       const j=await r.json();log(j.msg,j.ok?'ok':'err');}
   catch(e){log('Ошибка: '+e,'err');}
 }
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # тихо
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self._send(404, "not found", "text/plain")
            return
        page = (PAGE.replace("__USER__", getpass.getuser())
                    .replace("__PROXY__", DEFAULT_PROXY)
                    .replace("__SECRET__", DEFAULT_SECRET)
                    .replace("__CA__", DEFAULT_CA))
        self._send(200, page)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            data = {}
        user = (data.get("user") or getpass.getuser()).strip()
        subs = _subs(user, (data.get("agent") or "generic").strip(),
                     (data.get("proxy") or DEFAULT_PROXY).strip(),
                     data.get("secret") or "", data.get("ca") or DEFAULT_CA)
        try:
            if self.path == "/open":
                claude = _resolve_binary("claude")
                if not claude:
                    self._json({"ok": False, "msg": "'claude' не найден. Проверь, что "
                                "Claude Code установлен (ожидается в ~/.local/bin/claude)."})
                    return
                path = _write_script(subs, [claude])
                self._json({"ok": True, "msg": _open_terminal(path) +
                            f" Пользователь: {user}. Пиши запросы в терминале."})
            elif self.path == "/check":
                out = _run_check(subs)
                ok = "api.anthropic" in out or "error" in out or "message" in out
                self._json({"ok": ok, "msg": "Ответ: " + out +
                            "\n→ Инцидент (aws_access_key) появится в отчёте на сервере."})
            else:
                self._json({"ok": False, "msg": "unknown"})
        except Exception as e:
            self._json({"ok": False, "msg": f"Ошибка: {e}"})

    def _json(self, obj):
        self._send(200, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    port = _free_port()
    url = f"http://127.0.0.1:{port}/"
    httpd = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Data-Shield-Proxy launcher: {url}  (Ctrl+C для выхода)")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
