import asyncio
import json
import websockets
import os

# Słownik przechowujący aktywne połączenia: { "Kamil#a8f2": <websocket> }
connected_users = {}


async def handle_client(websocket):
    user_id = None
    try:
        async for message in websocket:
            data = json.loads(message)
            action = data.get("action")

            # 1. Rejestracja użytkownika w sieci
            if action == "register":
                user_id = data.get("id")
                if user_id:
                    connected_users[user_id] = websocket
                    print(f"[+] Zarejestrowano użytkownika: {user_id}")
                    await websocket.send(
                        json.dumps({"status": "registered", "id": user_id})
                    )

            # 2. Przekazywanie wiadomości WebRTC do konkretnego odbiorcy
            elif action in ["offer", "answer", "ice_candidate"]:

                # FIX #2 + #3 — odrzuć wiadomość jeśli nadawca nie jest zarejestrowany
                if not user_id:
                    print(f"[!] Odrzucono {action}: nadawca nie jest zarejestrowany.")
                    await websocket.send(
                        json.dumps(
                            {
                                "action": "error",
                                "message": "Musisz się najpierw zarejestrować.",
                            }
                        )
                    )
                    continue

                target_id = data.get("target")
                data["sender"] = user_id  # bezpieczne — user_id gwarantowany powyżej

                if target_id not in connected_users:
                    print(f"[-] Odrzucono: Użytkownik {target_id} jest offline.")
                    await websocket.send(
                        json.dumps(
                            {
                                "action": "error",
                                "message": f"Użytkownik {target_id} jest offline lub nie istnieje.",
                            }
                        )
                    )
                    continue

                # FIX #4 — obsługa martwych gniazd przy przekazywaniu
                try:
                    print(f"[*] Przekazywanie {action} od {user_id} do {target_id}")
                    await connected_users[target_id].send(json.dumps(data))
                except websockets.exceptions.ConnectionClosed:
                    # Stale połączenie — wyczyść i poinformuj nadawcę
                    print(
                        f"[-] Martwe gniazdo dla {target_id}, usuwam z rejestru."
                    )
                    del connected_users[target_id]
                    await websocket.send(
                        json.dumps(
                            {
                                "action": "error",
                                "message": f"Użytkownik {target_id} rozłączył się.",
                            }
                        )
                    )

    except websockets.exceptions.ConnectionClosed:
        pass
    except json.JSONDecodeError:
        print(f"[!] Odebrano nieprawidłowy JSON od {user_id or 'nieznanego klienta'}")
    finally:
        # Sprzątanie po wyłączeniu aplikacji przez użytkownika
        if user_id and user_id in connected_users:
            del connected_users[user_id]
            print(f"[-] Użytkownik rozłączony: {user_id}")


async def main():
    # Pobieranie portu ze zmiennych środowiskowych (dla chmury) lub użycie domyślnego 8765
    port = int(os.environ.get("PORT", 8765))

    # FIX #1 — ping_interval wykrywa i usuwa martwe połączenia (ghost connections).
    # Serwer wysyła ping co 20s; klient ma 10s na odpowiedź pong.
    # Bez tego: klienci którzy crashują lub tracą sieć zostają w connected_users
    # na zawsze, a kolejne oferty do nich cicho wysypują serwer.
    async with websockets.serve(
        handle_client,
        "0.0.0.0",
        port,
        ping_interval=20,
        ping_timeout=10,
    ):
        print(f"🚀 Serwer sygnalizacyjny wystartował na porcie {port}")
        print(f"   Nasłuchuję na 0.0.0.0:{port}")
        print(f"   Keepalive: ping co 20s, timeout 10s")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
