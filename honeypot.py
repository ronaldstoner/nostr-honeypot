#!/usr/bin/env python3
#
# Project:      nostr relay honeypot
# Members:      ronaldstoner
#
# NOTE: This script is a work in progress.

version = "0.1.0"

import json
import asyncio
import websockets

event_data = {}  # a dictionary to store event data

async def handle_connection(websocket, path):
    try:
        while True:
            raw_data = await websocket.recv()
            data = json.loads(raw_data)

            # Log the IP address, request, and content
            print("Received request from IP:", websocket.remote_address[0])
            print("Raw Data:", raw_data)
            #print("Request:", data)
            #print("Content:", data[1]["content"])


            print(data[0])
            if data[0] == "EVENT":
                # Store the event data
                event_data[data[1]['id']] = data
                print(f'Stored event data for id: {data[1]["id"]}')

            # Check for SQL injection attempts
            #print("Checking for SQL injection")
            if 'content' in data[1]:
                #print("Content:", data[1]["content"])
                if any(x in data[1]['content'] for x in ['SELECT', 'UPDATE', 'INSERT', 'DELETE']):
                    print(f"[ALERT]: Possible SQL injection attempt detected from {websocket.remote_address[0]}!")

            # Event Requests (Fake Out)
            if data[0] == 'REQ':
                print("Received request of type REQ")
                # Extract the ids from the request
                #ids = data[2]['ids']
                #print("Received ids:", ids)
                # Send a fake response indicating that the event note was accepted
                #response = {"status": "Accepted", "event": ids[0]}
                #response = {"EVENT", ids[0]}
                #await websocket.send(json.dumps(response))
                #continue

                # Extract the id of the requested event
                event_id = data[2]['ids'][0]
                print(event_id)

                # Extract the subscription ID
                subscription_id = data[1]
                print("Sub: ", subscription_id)

                # Retrieve the event data from the dictionary
                event = event_data.get(event_id)
                #if event:
                    # Send the event data as a response
                #    print(f"Sending back event {event}")
                #    await websocket.send(json.dumps(event))
                #else:
                    # Send a response indicating that the event could not be found
                #    response = {"status": "Error", "message": "Event not found"}
                if event:
                    # Send the event data along with the subscription ID as a response
                    response = ["EVENT", subscription_id, event]
                    print("Sending back", response)
                    try:
                        await websocket.send(json.dumps(response))
                    except:
                        print("error sennding back")
                else:
                    # Send a response indicating that the event could not be found
                    response = ["EVENT", subscription_id, {"status": "Error", "message": "Event not found"}]

            # Send a fake response indicating that the request was accepted
            #response = {"status": "Accepted"}
            #await websocket.send(json.dumps(response))
    except websockets.exceptions.ConnectionClosedError:
        print(f"Connection closed by remote client {websocket.remote_address[0]}")
    except Exception as e:
        print("Error:", e)

def on_connect(websocket, path):
    print(f"Client connected from {websocket.remote_address[0]}")
    print("Websocket headers:\n", websocket.request_headers)
    return handle_connection(websocket, path)

if __name__ == '__main__':
    port = 8080   # specify the port you want the honeypot to listen on
    start_server = websockets.serve(on_connect, '0.0.0.0', port)
    print(f"Raw relay is listening on 0.0.0.0:{port}")
    asyncio.get_event_loop().run_until_complete(start_server)
    while True:
        try:
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            print("Server interrupted. Gracefully closing connections.")
            start_server.ws_server.close()
            asyncio.get_event_loop().stop()
            break
