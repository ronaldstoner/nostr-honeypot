#!/usr/bin/env python3
#
# Project:      nostr relay honeypot
# Members:      ronaldstoner
#
# NOTE: This script is a work in progress.

version = "0.1.3.1"

import asyncio
import datetime
import json
import re
import websockets
from collections import defaultdict
from pymongo import MongoClient

event_data = {}     # dictionary to store event data
ip_scores = defaultdict(int)      # dictionary to store scores by IP
violated_rules = defaultdict(int)

# Load honeypot rules from json file
with open(r"rules.json") as f:
    rules = json.load(f)

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
try:
    db = client["relay"]
except:
    print("Could not connect to mongodb. Exiting.")
events_collection = db["events"]
pubkeys_collection = db["pubkeys"]


# Check and add event score and set 0 if none
def check_event(event_content, client_ip):
    event_score = 0
    for rule_id, rule in rules.items():
        if rule['regex']:
            if re.search(rule['regex'], event_content):
                event_score += rule['weight']
                violated_rules[rule_id] += 1
                print(f"\n - [ALERT] Rule {rule_id} - {rule['description']}\n   {client_ip} - Total Score: {ip_scores[client_ip] + event_score}\n   Offending Event Content: {json.loads(event_content)['content']}\n")
    ip_scores[client_ip] += event_score
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
            print(f"Received request from IP: {client_ip}")
            print("Raw Data:", raw_data)
            
            # Check if the pubkey exists in the pubkeys table
            pubkey = None
            if 'pubkey' in data[1]:
                print("pubkey found")
                pubkey = data[1]['pubkey']
                pubkey_record = pubkeys_collection.find_one({'pubkey': pubkey})
                if pubkey_record:
                    # Update the last_seen field
                    pubkeys_collection.update_one({'pubkey': pubkey}, {'$set': {'last_seen': datetime.datetime.now()}})
                else:
                    # Add the pubkey to the pubkeys table
                    pubkeys_collection.insert_one({'pubkey': pubkey, 'ip_address': client_ip, 'last_seen': datetime.datetime.now()})


            if data[0] == "EVENT":
                event = data[1]
                print("event: ", event)
                event_id = event['id']
                event_data[event_id] = event
                event_score = check_event(json.dumps(event), client_ip)

                # Store event in MongoDB
                try:
                    events_collection.insert_one(event)
                    print("Event written to mongodb.")
                except:
                    #["OK", "b1a649ebe8...", false, "error: could not connect to the database"]
                    response = ["OK", event_id, False, "error: could not write event to database"]
                    try:
                        await websocket.send(json.dumps(response))
                        print("DB Failed Response sent")
                    except:
                        print("Error sending db fail back")
                    print("Could not write to mongodb")
                    break

                # Send OK message
                ok_message = ["OK", event_id, True, ""]
                try:
                    await websocket.send(json.dumps(ok_message))    
                    print("OK Message: ", ok_message)
                    print("Sent OK message back")
                except:
                    print("Error sending OK back")

            if data[0] == 'REQ':
                print("REQ receieved:", data)
                subscription_id = data[1]

                event_id = None
                kinds = []

                for d in data[2:]:
                    if 'ids' in d:
                        event_id = d['ids'][0]
                        print("ID found:", event_id)
                    if 'kinds' in d:
                        kinds.extend(d['kinds'])
                        print("KINDs found:", kinds)

                if event_id is not None:
                    print(event_id)
                    # Search for the event in MongoDB
                    event = events_collection.find_one({"id": event_id}, { "_id": 0 })
                    
                    # If the event exists, send its contents back to the client
                    if event:
                        response = ["EVENT", subscription_id, event]
                        print("RESPONSE: ", response)
                        try:
                            await websocket.send(json.dumps(response))
                            # NIP-15 - End of Stored Events Notice
                            response = ["EOSE", subscription_id]
                            print("EOSE: ", response)
                            await websocket.send(json.dumps(response))
                            print("Found Response sent")
                        except:
                            print("Error sending event response back")
                    else:
                        response = ["EOSE", subscription_id]
                        try:
                            await websocket.send(json.dumps(response))
                            print("False Response sent")
                        except:
                            print("Error sending false back")

                for kind in kinds:
                    if kind == 0:
                        print("Metadata update")

                    if kind == 1:
                        response = ["OK", subscription_id, True, ""]
                        try:
                            await websocket.send(json.dumps(response))
                            print("OK response sent")
                        except:
                            print("Error sending OK response")

                    if kind == 2:
                        print("Relay server recommendation")

                    if kind == 3:
                        # Handle kind 3
                        print("Kind 3")

                    if kind == 4:
                        # Handle kind 4
                        print("Kind 4")

    except websockets.exceptions.ConnectionClosedError:
        print(f"Connection closed by remote client {client_ip}")
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    port = 8080 # specify the port you want the honeypot to listen on
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