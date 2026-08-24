# -*- coding: utf-8 -*-
"""
PC Monitor — чемна зупинка збирача. Викликається зі stop.bat.

1. Читає токен сесії з data\\session.token (без нього API відкидає POST —
   це захист від запитів зі сторонніх сайтів).
2. Просить /api/quit — монітор завершується сам і встигає дописати базу.
3. Чекає до 12 секунд, поки порт звільниться. Якщо монітор живий і після
   цього — stop.bat доб'є його через taskkill (крайній випадок).

Код виходу: 0 — зупинився чемно; 1 — не вдалося (нехай батник добиває).
"""
import json
import os
import socket
import sys
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
PORT = 8787
try:
    with open(os.path.join(BASE, "config.json"), encoding="utf-8") as f:
        PORT = int(json.load(f).get("dashboard_port", PORT))
except Exception:
    pass


def port_open():
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=0.4)
        s.close()
        return True
    except OSError:
        return False


def main():
    if not port_open():
        print("Монітор не запущено.")
        return 0

    token = ""
    try:
        with open(os.path.join(BASE, "data", "session.token"), encoding="utf-8") as f:
            token = f.read().strip()
    except OSError:
        pass

    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/api/quit", data=b"{}",
            headers={"Content-Type": "application/json", "X-PCMon-Token": token})
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print(f"Не вдалося попросити зупинку ({e}).")
        return 1

    # Дати збирачу дописати останні дані: він зливає чергу в базу до 15 с.
    for _ in range(24):
        if not port_open():
            print("Монітор зупинився чемно.")
            return 0
        time.sleep(0.5)
    print("Монітор не зупинився за 12 с.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
