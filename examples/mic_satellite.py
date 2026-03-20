"""Mic satellite example — streams I2S audio to HiveMind hub."""
try:
    import uasyncio as asyncio
    from machine import I2S, Pin
    import network
except ImportError:
    print("This example requires MicroPython with machine.I2S")
    raise SystemExit

from hivemind.client import HiveMindClient, MSG_BINARY
from hivemind.binary import BIN_STT_HANDLE, BIN_TTS_AUDIO

# Config
WIFI_SSID = "YOUR_SSID"
WIFI_PASS = "YOUR_PASSWORD"
HOST = "192.168.1.100"
PORT = 5678
USERNAME = "esp32"
ACCESS_KEY = "your_access_key"
PASSWORD = "your_password"

# I2S config for INMP441
I2S_SCK = 26
I2S_WS = 25
I2S_SD = 33
SAMPLE_RATE = 16000
CHUNK_SIZE = 1024


def on_binary(bin_type: int, data: bytes) -> None:
    """Handle incoming binary frames from the hub."""
    if bin_type == BIN_TTS_AUDIO:
        print(f"[TTS] Received {len(data)} bytes audio")
        # Play audio via I2S speaker here


async def main() -> None:
    """Connect WiFi, setup I2S mic, and stream audio to hub."""
    # Connect WiFi
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(WIFI_SSID, WIFI_PASS)
    while not wlan.isconnected():
        await asyncio.sleep(0.1)
    print(f"WiFi: {wlan.ifconfig()}")

    # Setup I2S mic
    mic = I2S(0, sck=Pin(I2S_SCK), ws=Pin(I2S_WS), sd=Pin(I2S_SD),
              mode=I2S.RX, bits=16, format=I2S.MONO,
              rate=SAMPLE_RATE, ibuf=4096)

    client = HiveMindClient(HOST, PORT, USERNAME, ACCESS_KEY, PASSWORD,
                            site_id="micropython-mic")
    client.on_binary = on_binary

    async def stream_audio() -> None:
        """Continuously read I2S mic and send audio chunks."""
        buf = bytearray(CHUNK_SIZE)
        while client.state == 5:  # READY
            num = mic.readinto(buf)
            if num:
                await client.send_binary(BIN_STT_HANDLE, bytes(buf[:num]))
            await asyncio.sleep_ms(10)

    async def on_ready() -> None:
        """Called when handshake completes."""
        print("Connected! Streaming audio...")
        asyncio.create_task(stream_audio())

    client.on_connected = on_ready
    await client.connect()


asyncio.run(main())
