"""
edge/mqtt_broker_sim.py
-------------------------
A minimal in-process publish/subscribe broker that mirrors the topic-based
MQTT model (publish/subscribe, named topics, QoS-style delivery) so that the
whole pipeline (device -> broker -> edge gateway) can run and be graded
without requiring a real Mosquitto broker or network/internet access.

WHY A SIMULATED BROKER, AND HOW TO SWAP IN REAL MQTT:
This prototype's IoT and edge modules are written against the small
interface below (`publish(topic, payload)` / `subscribe(topic, callback)`),
which intentionally matches the shape of the `paho-mqtt` client library
(`client.publish(topic, payload)`, `client.on_message`). To use a real
Mosquitto broker secured with TLS instead of this simulation:

    1. `pip install paho-mqtt`
    2. Configure Mosquitto with TLS certificates and a password file
       (see README.md, "Moving to a real MQTT broker").
    3. Replace `SimulatedMQTTBroker` with a thin adapter class that
       implements the same `publish`/`subscribe` methods using
       `paho.mqtt.client.Client`, `tls_set()`, and `username_pw_set()`.

No other module needs to change, because `edge/gateway.py` and
`iot/simulator.py` only depend on this interface, not on the transport.
"""

import threading
from collections import defaultdict


class SimulatedMQTTBroker:
    def __init__(self):
        self._subscribers = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, topic: str, callback):
        with self._lock:
            self._subscribers[topic].append(callback)

    def publish(self, topic: str, payload: dict, qos: int = 1):
        """Deliver payload to every callback subscribed to this exact topic."""
        with self._lock:
            callbacks = list(self._subscribers.get(topic, []))
        for cb in callbacks:
            # Each callback runs in its own thread to emulate the
            # asynchronous, non-blocking delivery model of a real broker.
            threading.Thread(target=cb, args=(topic, payload), daemon=True).start()


# A single process-wide broker instance shared by the IoT simulator and the
# edge gateway, standing in for the Mosquitto broker in this local demo.
broker = SimulatedMQTTBroker()
