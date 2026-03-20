"""Text satellite example — sends utterances, receives speak responses."""
import sys
try:
    import uasyncio as asyncio
    import network
except ImportError:
    import asyncio
    network = None

from hivemind.client import HiveMindClient

# WiFi config (MicroPython only)
WIFI_SSID = "YOUR_SSID"
WIFI_PASS = "YOUR_PASSWORD"

# HiveMind config
HOST = "192.168.1.100"
PORT = 5678
USERNAME = "esp32"
ACCESS_KEY = "your_access_key"
PASSWORD = "your_password"


def on_bus_message(msg_type, data, context):
    """Handle incoming bus messages from the hub."""
    print(f"[BUS] {msg_type}: {data}")
    if msg_type == "speak":
        utterance = data.get("utterance", "")
        print(f"[SPEAK] {utterance}")


async def main():
    """Connect to HiveMind hub and send a test utterance."""
    if network:
        wlan = network.WLAN(network.STA_IF)
        wlan.active(True)
        wlan.connect(WIFI_SSID, WIFI_PASS)
        while not wlan.isconnected():
            await asyncio.sleep(0.1)
        print(f"WiFi connected: {wlan.ifconfig()}")

    client = HiveMindClient(HOST, PORT, USERNAME, ACCESS_KEY, PASSWORD,
                            site_id="micropython-text")
    client.on_bus_message = on_bus_message

    async def on_ready():
        """Called when handshake completes."""
        print("Connected! Sending utterance...")
        await client.send_utterance("hello world")

    client.on_connected = on_ready
    await client.connect()


asyncio.run(main())
