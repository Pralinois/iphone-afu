# lang: Python 3.10+
# file: modules/pymd3_compat.py
# deps: stdlib (asyncio, inspect, concurrent.futures)
# skill refs: ios-pentesting-tricks §1 (non-jailbreak setup)

"""Compatibility shim pymobiledevice3 : supporte l'API sync (4.x) et async (>=5.x).

La génération async expose list_devices/create_using_usbmux/LockdownClient.get_value
comme coroutines ; l'ancienne est synchrone. `run_maybe_async` accepte les deux.
"""

import asyncio
import inspect
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

T = TypeVar("T")


def run_maybe_async(value: Any) -> Any:
    """
    Retourne la valeur directement si elle n'est pas une coroutine.
    Sinon l'exécute :
      - asyncio.run() si aucune boucle n'est active (cas CLI) ;
      - dans un thread dédié si une boucle tourne déjà (cas TUI/worker),
        pour éviter « asyncio.run() cannot be called from a running event loop ».
    """
    if not inspect.iscoroutine(value):
        return value
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(value)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, value).result()
