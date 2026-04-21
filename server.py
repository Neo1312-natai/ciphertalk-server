import os
import asyncio
import websockets
import json

# Uniwersalny magazyn pokoi
rooms = {}

async def universal_handler(websocket, path=None):
    current_room = None
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
            except:
                continue

            action = data.get("action")
            room_id = str(data.get("room_id")) # Ujednolicamy ID jako tekst

            if action == "join":
                current_room = room_id
                if room_id not in rooms:
                    rooms[room_id] = set()
                rooms[room_id].add(websocket)
                print(f"Zalogowano do pokoju: {room_id}. Osób w środku: {len(rooms[room_id])}")

            elif action == "relay" or "type" in data: 
                # Dodajemy obsługę różnych formatów (stary kod mógł mieć "type")
                if current_room in rooms:
                    targets = [ws for ws in rooms[current_room] if ws != websocket]
                    if targets:
                        # Rozsyłamy do wszystkich innych w pokoju
                        await asyncio.gather(*[ws.send(message) for ws in targets])

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if current_room in rooms and websocket in rooms[current_room]:
            rooms[current_room].remove(websocket)
            if not rooms[current_room]:
                del rooms[current_room]

async def main():
    # Render sam przydzieli port, nie ustawiaj go na sztywno jako 9001
    port = int(os.environ.get("PORT", 8080)) 
    async with websockets.serve(universal_handler, "0.0.0.0", port):
        print(f"Uniwersalny Relay startuje na porcie {port}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
