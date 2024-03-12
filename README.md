# lwmqtt

[![Test](https://github.com/256dpi/lwmqtt/actions/workflows/test.yml/badge.svg)](https://github.com/256dpi/lwmqtt/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/release/256dpi/lwmqtt.svg)](https://github.com/256dpi/lwmqtt/releases)

The "**L**ight **W**eight **MQTT**" library implements a MQTT 3.1.1 client that is optimized to be used in embedded and constraint systems. It can be used with any operating system and network stack and only requires a handful of callbacks for a full integration. The project is derived from the [Paho MQTT Embeded C](https://github.com/eclipse/paho.mqtt.embedded-c), [gomqtt](https://github.com/gomqtt) and [mosquitto](https://github.com/eclipse/mosquitto) project.

## Installation

The library is available on [PlatformIO](https://registry.platformio.org/libraries/256dpi/LWMQTT). You can install it by running: `pio lib install "256dpi/LWMQTT"`. 

## Release Management

- Update version in `library.json`.
- Create release on GitHub.
