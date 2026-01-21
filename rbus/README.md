# RBus Wireshark Dissector

A Wireshark protocol dissector for analyzing RBus (RDK Bus) messaging traffic.

## Table of Contents

- [RBus Wireshark Dissector](#rbus-wireshark-dissector)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites)
    - [Build Dependencies](#build-dependencies)
    - [Runtime Dependencies](#runtime-dependencies)
  - [Building](#building)
    - [Build Options](#build-options)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Capturing RBus Traffic](#capturing-rbus-traffic)
      - [TCP Capture (Direct)](#tcp-capture-direct)
      - [Unix Domain Socket Capture (May not work on MacOS)](#unix-domain-socket-capture-may-not-work-on-macos)
    - [Display Filters](#display-filters)
      - [Header Filters](#header-filters)
      - [Flag Filters](#flag-filters)
      - [Method and Message Type Filters](#method-and-message-type-filters)
      - [Property and Parameter Filters](#property-and-parameter-filters)
      - [Event Filters](#event-filters)
      - [Advanced Filters](#advanced-filters)
      - [Example Complex Filters](#example-complex-filters)
    - [Preferences](#preferences)
  - [Project Structure](#project-structure)
  - [Troubleshooting](#troubleshooting)
    - [Plugin Not Loading](#plugin-not-loading)
    - [Cannot Capture Unix Sockets](#cannot-capture-unix-sockets)
    - [Build Errors](#build-errors)
  - [Development](#development)
    - [Debug Mode](#debug-mode)
  - [Contributing](#contributing)
  - [License](#license)
  - [References](#references)

## Overview

RBus is a lightweight messaging system used for inter-process communication (IPC) in RDK devices. This dissector enables network traffic analysis and debugging by decoding:

- rtMessage header format
- MessagePack encoded payloads
- Both Unix Domain Socket and TCP transports

## Prerequisites

### Build Dependencies

- **Wireshark Development Headers** (3.0.0 or later)
  - Ubuntu/Debian: `sudo apt-get install wireshark-dev libwireshark-dev`
  - Fedora/RHEL: `sudo dnf install wireshark-devel`
  - macOS: `brew install wireshark` (includes headers)

- **GLib 2.0** (2.32.0 or later)
  - Ubuntu/Debian: `sudo apt-get install libglib2.0-dev`
  - Fedora/RHEL: `sudo dnf install glib2-devel`
  - macOS: `brew install glib`

- **CMake** (3.10 or later)
  - Ubuntu/Debian: `sudo apt-get install cmake`
  - Fedora/RHEL: `sudo dnf install cmake`
  - macOS: `brew install cmake`

- **pkg-config**
  - Ubuntu/Debian: `sudo apt-get install pkg-config`
  - Fedora/RHEL: `sudo dnf install pkgconfig`
  - macOS: `brew install pkg-config`

- **MessagePack** (optional, for payload decoding)
  - Ubuntu/Debian: `sudo apt-get install libmsgpack-dev`
  - Fedora/RHEL: `sudo dnf install msgpack-devel`
  - macOS: `brew install msgpack`

### Runtime Dependencies

- Wireshark 3.0.0 or later

## Building

```bash
# Create build directory
mkdir build && cd build

# Configure
cmake ..

# Build
make

# Install (copies plugin to Wireshark plugin directory)
sudo make install
```

### Build Options

```bash
# Specify custom Wireshark plugin directory
cmake -DWIRESHARK_PLUGIN_DIR=/path/to/plugins ..

# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

## Installation

The plugin will be installed to the Wireshark plugin directory:
- Linux: `~/.local/lib/wireshark/plugins/` or `/usr/lib/wireshark/plugins/`
- macOS: `~/.local/lib/wireshark/plugins/` or `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`

Verify installation by checking Wireshark → About → Plugins. You should see "rbus" listed.

## Usage

### Capturing RBus Traffic

**Important:** Before restarting `rtrouted` with TCP transport, ensure all running RBus clients are stopped. This includes processes like `rbus-elements`, `rbuscli`, or any other components connected to the RBus daemon.

#### TCP Capture (Direct)

Start RBus using TCP transport:

```bash
# Create a rbus client configuration
sudo sh -c 'echo "tcp://127.0.0.1:10002" > /etc/rbus_client.conf'

# Start RBus using the default rbus plugin port (-f keeps rtrouted in the foreground)
rtrouted -f -s tcp://127.0.0.1:10002

# Restart any clients like rbus-elements

# Capture to a file on default port 10002
tcpdump -i lo -w rbus.pcap tcp port 10002

# Open in Wireshark
wireshark rbus.pcap

# Or use Wireshark directly
wireshark -i lo0 -k -f "tcp port 10002"

# Use rbuscli to generate some traffic
rbuscli discallcomponents
rbuscli get Device.DeviceInfo.
```

#### Unix Domain Socket Capture (May not work on MacOS)

Wireshark 3.0+ can capture Unix socket traffic directly:

```bash
# List available Unix sockets
dumpcap -D

# Capture specific socket
dumpcap -i unix:///tmp/rtrouted -w rbus.pcap

# Open in Wireshark
wireshark rbus.pcap

# Or use Wireshark directly
wireshark -i unix:///tmp/rtrouted -k
```

### Display Filters

The dissector provides comprehensive display filters for analyzing RBus traffic:

#### Header Filters

```
# Filter by topic (destination)
rbus.header.topic == "Device.WiFi.Radio.1"

# Wildcard topic matching
rbus.header.topic matches "Device\\.WiFi.*"

# Filter by reply topic
rbus.header.reply_topic == "rbus.rbuscli.INBOX.12345"

# Filter by sequence number
rbus.header.sequence == 12345

# Filter by header length
rbus.header.length > 100

# Filter by payload length
rbus.header.payload_length > 0

# System messages (daemon routing)
rbus.header.topic contains "_RTROUTED"
```

#### Flag Filters

```
# Request messages
rbus.header.flags.request

# Response messages
rbus.header.flags.response

# Undeliverable messages
rbus.header.flags.undeliverable

# Raw binary payload
rbus.header.flags.raw_binary

# Encrypted messages
rbus.header.flags.encrypted
```

#### Method and Message Type Filters

```
# Filter by method type
rbus.method == "METHOD_RESPONSE"
rbus.method == "METHOD_GETPARAMETERVALUES"
rbus.method == "METHOD_SETPARAMETERVALUES"

# Event publications
rbus.event_name == "Device.WiFi.Radio.1.StatusChange"

# Method invocations
rbus.invoke_method_name == "Device.Reboot()"

# Messages with errors
rbus.error_code != 0

# Successful responses
rbus.error_code == 0
```

#### Property and Parameter Filters

```
# Filter by property name
rbus.property.name == "Status"

# Filter by property value
rbus.property.value.string == "Reboot scheduled"

# Combined name=value filtering
rbus.property.namevalue == "Device.WiFi.SSID.1.Enable=true"

# Filter by parameter name
rbus.parameter.name == "Device.WiFi.SSID.1.SSID"

# Combined parameter name=value filtering
rbus.parameter.namevalue contains "SSID"

# Property count
rbus.property_count > 0

# Parameter count
rbus.param_count > 0
```

#### Event Filters

```
# Event type
rbus.event_type == 0    # RBUS_EVENT_OBJECT_CREATED
rbus.event_type == 1    # RBUS_EVENT_OBJECT_DELETED
rbus.event_type == 2    # RBUS_EVENT_VALUE_CHANGED

# Events with data
rbus.has_event_data == 1

# Event subscription duration
rbus.duration > 0

# Event interval
rbus.interval > 0
```

#### Advanced Filters

```
# Combine filters with logical operators
rbus.header.flags.response && rbus.error_code == 0

# Filter sessions
rbus.session_id == 12345

# Component filtering
rbus.component_name == "WebPA"
rbus.component_id == 1

# Roundtrip timing (microseconds)
rbus.header.roundtrip.t1 > 0

# OpenTelemetry trace filtering
rbus.ot_parent != ""

# Failed operations
rbus.failed_element

# Messages with payload
rbus.payload
```

#### Example Complex Filters

```
# All WiFi-related set operations
rbus.header.topic matches "Device\\.WiFi.*" && rbus.method == "METHOD_SETPARAMETERVALUES"

# Failed responses for specific component
rbus.component_name == "WebPA" && rbus.error_code != 0

# Event publications for value changes
rbus.event_name && rbus.event_type == 2

# High-latency responses (T5-T1 > 100ms = 100000 microseconds)
rbus.header.flags.response && (rbus.header.roundtrip.t5 - rbus.header.roundtrip.t1) > 100000
```

### Preferences

Configure dissector preferences via Edit → Preferences → Protocols → RBUS:

- **TCP Port**: Default port number (10002)
- **MessagePack Depth Limit**: Maximum nesting depth for payload decoding (16)

## Project Structure

```
dissector/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── include/
│   └── rbus-protocol.h     # Protocol definitions
├── src/
    └── packet-rbus.c       # Main dissector implementation
```

## Troubleshooting

### Plugin Not Loading

1. Check plugin directory:
   ```bash
   wireshark -v | grep "Personal Plugins"
   wireshark -v | grep "Global Plugins"
   ```

2. Verify plugin file exists and has correct permissions:
   ```bash
   ls -la ~/.local/lib/wireshark/plugins/*/rbus.so
   ```

3. Check Wireshark logs for errors:
   ```bash
   wireshark -v
   ```

### Cannot Capture Unix Sockets

- Ensure you have root/sudo privileges
- For Wireshark < 3.0, use socat bridge method
- Verify socket exists: `ls -la /tmp/rtrouted`

### Build Errors

- Verify all dependencies are installed
- Check pkg-config can find Wireshark: `pkg-config --modversion wireshark`
- Ensure GLib is found: `pkg-config --modversion glib-2.0`

## Development

### Debug Mode

```bash
# Build in debug mode
cmake -DCMAKE_BUILD_TYPE=Debug ..
make

# Run Wireshark with debug output
wireshark -o 'rbus.debug:TRUE' -r test.pcap
```

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style conventions
- Documentation is updated

## License

Apache License 2.0 - See LICENSE file for details

## References

- [RBus GitHub Repository](https://github.com/rdkcentral/rbus)
- [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html_chunked/)
- [MessagePack Specification](https://msgpack.org/)

