#!/usr/bin/env python3
#
# Project:      nostr relay honeypot
# Members:      ronaldstoner
#
# NOTE: This script is a work in progress.

version = "0.1.2"

import asyncio
import json
import re
import websockets
from collections import defaultdict

event_data = {}     # dictionary to store event data
ip_scores = defaultdict(int)      # dictionary to store scores by IP
violated_rules = defaultdict(int)

# Load honeypot rules from json file
with open(r"rules.json") as f:
    rules = json.load(f)

# Check and add event score and set 0 if none
def check_event(event_content, client_ip):
    event_score = 0
    for rule_id, rule in rules.items():
        if rule['regex']:
            if re.search(rule['regex'], event_content):
                event_score += rule['weight']
                violated_rules[rule_id] += 1
                print(f"\n - [ALERT] Rule {rule_id} detected - {rule['description']}\n   {client_ip} - Total Score: {ip_scores[client_ip]}\n   Offending Event Content: {json.loads(event_content)['content']}\n")
    return event_score

# On Connection
def on_connect(websocket, path):
    print(f"Client connected from {websocket.remote_address[0]}")
    #print("Websocket headers:\n", websocket.request_headers)
    return handle_connection(websocket, path)

# Connection Handler
async def handle_connection(websocket, path):
    try:
        while True:
            raw_data = await websocket.recv()
            data = json.loads(raw_data)

            # Log the IP address, request, and content
            client_ip = websocket.remote_address[0]
            #print(f"Received request from IP: {client_ip}")
            #print("Raw Data:", raw_data)

            if data[0] == "EVENT":
                event = data[1]
                #print("event: ", event)
                event_id = event['id']
                event_data[event_id] = event
                event_score = check_event(json.dumps(event), client_ip)
                ip_scores[client_ip] += event_score
                #if event_score > 0:
                    #print(f"[ALERT] IP: {websocket.remote_address[0]} has a score of {event_score}")
                #else:
                #    print(f"IP: {websocket.remote_address[0]} has a score of {event_score}")

                # Send OK message
                ok_message = ["OK", event_id, True, "Event accepted"]
                try:
                    await websocket.send(json.dumps(ok_message))
                except:
                    print("Error sending OK back")

            if data[0] == 'REQ':
                subscription_id = data[1]
                if 'ids' in data[2]:
                    event_id = data[2]['ids'][0]
                    event = event_data.get(event_id)
                    if event:
                        response = ["EVENT", subscription_id, event]
                        try:
                            await websocket.send(json.dumps(response))
                            #print("Response sent")
                        except:
                            print("Error sending back")
                    else:
                        response = ["OK", subscription_id, False, "Error: Event not found"]
                        try:
                            await websocket.send(json.dumps(response))
                            #print("Response sent")
                        except:
                            print("Error sending back")

    except websockets.exceptions.ConnectionClosedError:
        print(f"Connection closed by remote client {client_ip}")
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    port = 8080   # specify the port you want the honeypot to listen on
    start_server = websockets.serve(on_connect, '0.0.0.0', port)
    print(f"\nHoneypot relay is listening on 0.0.0.0:{port}")

    asyncio.get_event_loop().run_until_complete(start_server)
    while True:
        try:
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            print("\nTally of IP scores:")
            for ip, score in ip_scores.items():
                print(f"{ip}: {score}")
            break