# RBus Wire Protocol Documentation

This document describes the RBus (RDK Bus) wire protocol based on analysis of the source code in `/rbus/` and the official RBus WireProtocol specification.

## Table of Contents

1. [Overview](#overview)
2. [Protocol Stack](#protocol-stack)
3. [Message Header (rtMessage)](#message-header-rtmessage)
4. [MessagePack Payload](#messagepack-payload)
5. [Control Messages](#control-messages)
6. [Message Structures](#message-structures)
7. [Data Type Encoding](#data-type-encoding)
8. [Security Considerations](#security-considerations)
9. [Appendix](#appendix)
10. [Error Codes](#error-codes)
11. [Result Code Calculation](#result-code-calculation)
12. [Sessions and Transactions](#sessions-and-transactions)
13. [OpenTelemetry Integration](#opentelemetry-integration)
14. [Control Data Field](#control-data-field)
15. [Example Packet Decodes](#example-packet-decodes)
16. [Notes](#notes)
17. [References](#references)


## Overview

RBus is a message bus protocol used in RDK (Reference Design Kit) systems for inter-component communication. It uses:
- **Transport**: Unix Domain Sockets or TCP
- **Header Format**: Custom rtMessage binary header
- **Payload Encoding**: MessagePack

## Protocol Stack

```
┌─────────────────────────────────────┐
│      RBus Application Layer         │
│  (Methods, Properties, Events)      │
├─────────────────────────────────────┤
│    MessagePack Payload Layer        │
│ (Type-Length-Value encoding)        │
├─────────────────────────────────────┤
│    rtMessage Header Layer           │
│  (Routing, Flags, Timestamps)       │
├─────────────────────────────────────┤
│   Transport Layer (UDS/TCP)         │
└─────────────────────────────────────┘
```

## Message Header (rtMessage)

### Header Structure

The rtMessage header **begins at offset 0** with an opening marker and is bookended by a closing marker. All multi-byte integers are in **big-endian** (network byte order).

| Offset | Size | Field               | Type    | Description                                          |
|--------|------|---------------------|---------|------------------------------------------------------|
| 0      | 2    | Opening Marker      | uint16  | Protocol marker (0xAAAA) - marks header start        |
| 2      | 2    | Version             | uint16  | Protocol version (currently 2)                       |
| 4      | 2    | Header Length       | uint16  | Total header size in bytes                           |
| 6      | 4    | Sequence Number     | uint32  | Message sequence number                              |
| 10     | 4    | Flags               | uint32  | Message flags (see below)                            |
| 14     | 4    | Control Data        | uint32  | Control flags and routing metadata                   |
| 18     | 4    | Payload Length      | uint32  | Payload size in bytes                                |
| 22     | 4    | Topic Length        | uint32  | Length of topic string                               |
| 26     | N    | Topic               | string  | Destination topic (variable length)                  |
| 26+N   | 4    | Reply Topic Length  | uint32  | Length of reply topic string                         |
| 30+N   | M    | Reply Topic         | string  | Reply destination topic (variable length)            |
| *      | 20   | Roundtrip Times     | 5×uint32| Optional: T1-T5 timestamps (if MSG_ROUNDTRIP_TIME)  |
| †      | 2    | Closing Marker      | uint16  | Header closing marker (0xAAAA) - marks header end    |

**Note**: Offsets marked with * and † are variable based on topic lengths and optional fields.

**Important**: The header structure is enclosed by markers at both ends:
- **Opening Marker** (0xAAAA) at offset 0 marks the start of the header
- **Closing Marker** (0xAAAA) at the end marks where the header ends and payload begins

### Header Size Calculation

Without roundtrip times:
```
header_length = 32 + strlen(topic) + strlen(reply_topic)
```

With roundtrip times (when `MSG_ROUNDTRIP_TIME` is defined):
```
header_length = 52 + strlen(topic) + strlen(reply_topic)
```

### Message Flags

| Bit  | Mask | Name                          | Description                                      |
|------|------|-------------------------------|--------------------------------------------------|
| 0    | 0x01 | rtMessageFlags_Request        | Request message                                  |
| 1    | 0x02 | rtMessageFlags_Response       | Response message                                 |
| 2    | 0x04 | rtMessageFlags_Undeliverable  | Message could not be delivered                   |
| 3    | 0x08 | rtMessageFlags_Tainted        | Message is tainted (for benchmarking)            |
| 4    | 0x10 | rtMessageFlags_RawBinary      | Raw binary payload (not MessagePack)             |
| 5    | 0x20 | rtMessageFlags_Encrypted      | Encrypted payload                                |

### Roundtrip Timestamps

When compiled with `MSG_ROUNDTRIP_TIME`, five timestamps are included:

| Field | Description                                                   |
|-------|---------------------------------------------------------------|
| T1    | Time at which consumer sends the request to daemon            |
| T2    | Time at which daemon receives the message from consumer       |
| T3    | Time at which daemon writes to provider socket                |
| T4    | Time at which provider sends back the response                |
| T5    | Time at which daemon received the response                    |

All timestamps are 32-bit unsigned integers representing Unix epoch time.

## MessagePack Payload

The payload is encoded using MessagePack format. The structure varies by method type.

### RBus Value Types

RBus supports two type systems:

**CCSP/TR-181 Data Model Types (Legacy, 0x00-0x05):**

Used by legacy CCSP components and TR-181 data model implementations:

| Type ID | Name          | Description                      |
|---------|---------------|----------------------------------|
| 0x00    | ccsp_string   | String value                     |
| 0x01    | ccsp_int      | Signed integer                   |
| 0x02    | ccsp_unsignedInt | Unsigned integer              |
| 0x03    | ccsp_boolean  | Boolean value                    |
| 0x04    | ccsp_dateTime | Date/Time value                  |
| 0x05    | ccsp_base64   | Base64 encoded data              |

**RBus Native Types (0x500-0x512):**

Native RBus type system with fine-grained type control:

| Type ID | Name          | Description                      |
|---------|---------------|----------------------------------|
| 0x500   | RBUS_BOOLEAN  | Boolean value (true/false)       |
| 0x501   | RBUS_CHAR     | Character (1 byte)               |
| 0x502   | RBUS_BYTE     | Unsigned byte                    |
| 0x503   | RBUS_INT8     | 8-bit signed integer             |
| 0x504   | RBUS_UINT8    | 8-bit unsigned integer           |
| 0x505   | RBUS_INT16    | 16-bit signed integer            |
| 0x506   | RBUS_UINT16   | 16-bit unsigned integer          |
| 0x507   | RBUS_INT32    | 32-bit signed integer            |
| 0x508   | RBUS_UINT32   | 32-bit unsigned integer          |
| 0x509   | RBUS_INT64    | 64-bit signed integer            |
| 0x50A   | RBUS_UINT64   | 64-bit unsigned integer          |
| 0x50B   | RBUS_SINGLE   | 32-bit float                     |
| 0x50C   | RBUS_DOUBLE   | 64-bit double                    |
| 0x50D   | RBUS_DATETIME | Date/Time structure              |
| 0x50E   | RBUS_STRING   | Null-terminated string           |
| 0x50F   | RBUS_BYTES    | Byte array                       |
| 0x510   | RBUS_PROPERTY | Property instance                |
| 0x511   | RBUS_OBJECT   | Object instance                  |
| 0x512   | RBUS_NONE     | No value                         |

### Method Types

The following method types are defined:

| Method                          | Direction | Description                               |
|---------------------------------|-----------|-------------------------------------------|
| METHOD_SETPARAMETERVALUES       | Request   | Set parameter value(s)                    |
| METHOD_GETPARAMETERVALUES       | Request   | Get parameter value(s)                    |
| METHOD_GETPARAMETERNAMES        | Request   | Get parameter names (discovery)           |
| METHOD_SETPARAMETERATTRIBUTES   | Request   | Set parameter attributes                  |
| METHOD_GETPARAMETERATTRIBUTES   | Request   | Get parameter attributes                  |
| METHOD_COMMIT                   | Request   | Commit a session                          |
| METHOD_ADDTBLROW                | Request   | Add table row                             |
| METHOD_DELETETBLROW             | Request   | Delete table row                          |
| METHOD_RPC                      | Request   | Remote procedure call                     |
| METHOD_SUBSCRIBE                | Request   | Subscribe to event                        |
| METHOD_UNSUBSCRIBE              | Request   | Unsubscribe from event                    |
| METHOD_OPENDIRECT_CONN          | Request   | Open direct connection                    |
| METHOD_CLOSEDIRECT_CONN         | Request   | Close direct connection                   |
| METHOD_RESPONSE                 | Response  | Response to any method                    |

**Note on Success Codes**: Both 0 and 100 are treated as success in METHOD_RESPONSE messages. Implementations should check for `status == 0 || status == 100`.

## Control Messages

Control messages are sent between components and rtrouted to manage subscriptions and query routing information. They use JSON encoding in the payload (not MessagePack) and do not have the RawBinary flag set.

### Subscribe/Unsubscribe Messages

**RTMessage Envelope**:
- Flags: `0x01` (Request, without RawBinary flag)
- Topic: `_RTROUTED.INBOX.SUBSCRIBE` or similar router control topic
- Payload Encoding: JSON (RFC 8259)

**Subscribe Request**:
```json
{
  "add": 1,
  "topic": "<topic-to-subscribe>",
  "route_id": 1
}
```

**Unsubscribe Request**:
```json
{
  "add": 0,
  "topic": "<topic-to-unsubscribe>",
  "route_id": 1
}
```

**Field Definitions**:

| Field    | Type    | Description                          |
|----------|---------|--------------------------------------|
| add      | integer | 1 = subscribe, 0 = unsubscribe       |
| topic    | string  | Topic pattern to subscribe/unsubscribe |
| route_id | integer | Route identifier (typically 1)       |

**Note**: The `route_id` field is currently always set to 1 and is reserved for future routing enhancements.

### Discovery Messages

Discovery messages allow components to query the router's routing table to discover registered elements and components.

#### Query Wildcard Destinations

Resolves partial paths to discover matching registered topics.

**RTMessage Envelope**:
- Topic: `_RTROUTED.INBOX.QUERY`
- Flags: `0x01` (Request)
- Payload Encoding: JSON

**Request Format**:
```json
{
  "expression": "Device.WiFi."
}
```

**Response Format**:
```json
{
  "result": 0,
  "count": 3,
  "items": [
    "Device.WiFi.SSID",
    "Device.WiFi.Enable", 
    "Device.WiFi.AccessPoint."
  ]
}
```

**Field Definitions**:

| Field      | Type             | Description                      |
|------------|------------------|----------------------------------|
| expression | string           | Partial path or wildcard pattern |
| result     | integer          | Status code (0=success)          |
| count      | integer          | Number of matching topics        |
| items      | array of strings | List of matching topic paths     |

**Use Case**: Used when a component needs to discover what elements are registered under a partial path.

#### Discover Object Elements

Enumerates all topics registered for a specific route/component.

**RTMessage Envelope**:
- Topic: `_enumerate_elements`
- Flags: `0x01` (Request)
- Payload Encoding: JSON

**Request Format**:
```json
{
  "expression": "Device.WiFi.SSID"
}
```

**Response Format**:
```json
{
  "count": 5,
  "items": [
    "Device.WiFi.SSID",
    "Device.WiFi.Enable",
    "Device.WiFi.Channel",
    "Device.WiFi.Standard",
    "Device.WiFi.AccessPoint."
  ]
}
```

#### Discover Element Objects

Reverse lookup: finds which route owns a specific topic.

**RTMessage Envelope**:
- Topic: `_trace_origin_object`
- Flags: `0x01` (Request)
- Payload Encoding: JSON

**Request Format**:
```json
{
  "expression": "Device.WiFi.SSID"
}
```

**Response Format**:
```json
{
  "count": 1,
  "items": [
    "Device.WiFi."
  ]
}
```

**Use Case**: Determines which provider component owns a specific element path.

#### Discover Registered Components

Lists all active component routes registered with the router.

**RTMessage Envelope**:
- Topic: `_registered_components`
- Flags: `0x01` (Request)
- Payload Encoding: JSON

**Request Format**:
```json
{}
```

**Response Format**:
```json
{
  "count": 4,
  "items": [
    "Device.WiFi.",
    "Device.DeviceInfo.",
    "Device.Logging.",
    "Device.Time."
  ]
}
```

**Field Definitions**:

| Field | Type             | Description                          |
|-------|------------------|--------------------------------------|
| count | integer          | Number of registered routes          |
| items | array of strings | List of route expressions (excludes internal "_" prefixed routes) |

**Note**: This only returns non-internal routes. Routes starting with "_" (router control topics) are filtered out.

### Advisory Messages

Advisory messages are broadcast by rtrouted to notify subscribers about client connection lifecycle events.

**RTMessage Envelope**:
- Topic: `_RTROUTED.ADVISORY`
- Flags: `0x00` (no flags)
- Payload Encoding: JSON

**Advisory Event Format**:
```json
{
  "event": 0,
  "inbox": "rbus.component.INBOX.12345"
}
```

**Field Definitions**:

| Field | Type    | Description                                  |
|-------|---------|----------------------------------------------|
| event | integer | Event type (0=connect, 1=disconnect)         |
| inbox | string  | Inbox topic of the connecting/disconnecting client |

**Event Types**:

| Code | Name                     | Description                              |
|------|--------------------------|------------------------------------------|
| 0    | rtAdviseClientConnect    | Component connected and registered inbox |
| 1    | rtAdviseClientDisconnect | Component disconnected                   |

**Use Case**: Components can subscribe to `_RTROUTED.ADVISORY` to monitor when other components join or leave the bus. This is useful for service discovery and graceful degradation.

### Diagnostic Messages

Diagnostic messages allow administrators to query router state and enable debugging features.

**RTMessage Envelope**:
- Topic: `_RTROUTED.INBOX.DIAG`
- Flags: `0x01` (Request)
- Payload Encoding: JSON

**Diagnostic Commands**:

| Command                  | Description                            |
|--------------------------|----------------------------------------|
| enableVerboseLogs        | Enable verbose logging in rtrouted     |
| disableVerboseLogs       | Disable verbose logging                |
| logRoutingStats          | Dump routing statistics to logs        |
| logRoutingTopics         | List all registered topics             |
| logRoutingRoutes         | List all active routes                 |
| enableTrafficMonitor     | Enable message traffic monitoring      |
| disableTrafficMonitor    | Disable traffic monitoring             |
| resetBenchmarkData       | Clear performance benchmark counters   |
| dumpBenchmarkData        | Output benchmark data to logs          |
| heartbeat                | Check if router is responsive          |
| shutdown                 | Gracefully shut down router            |

**Request Format** (example):
```json
{
  "_RTROUTED.INBOX.DIAG.KEY": "logRoutingStats"
}
```

**Note**: Diagnostic messages are intended for debugging and administrative purposes only. Production code should not rely on these messages.

### Router Control Topic Summary

| Topic                          | Purpose                        | Request Format | Response Format    |
|--------------------------------|--------------------------------|----------------|--------------------|
| _RTROUTED.INBOX.SUBSCRIBE      | Manage subscriptions           | JSON           | JSON               |
| _RTROUTED.INBOX.QUERY          | Discover wildcard destinations | JSON           | JSON               |
| _enumerate_elements            | List route elements            | JSON           | JSON               |
| _trace_origin_object           | Reverse route lookup           | JSON           | JSON               |
| _registered_components         | List active components         | JSON           | JSON               |
| _RTROUTED.ADVISORY             | Connection lifecycle events    | N/A            | JSON (broadcast)   |
| _RTROUTED.INBOX.DIAG           | Diagnostic commands            | JSON           | Varies             |

### RBus Metadata Structure

All RBus messages include a metadata structure at the end of the MessagePack payload. This metadata provides routing information and distributed tracing context.

**Structure**:

```
[ method_name, ot_parent, ot_state, offset ]
```

| Field        | Type    | Description                                                          |
|--------------|---------|----------------------------------------------------------------------|
| method_name  | string  | The method name (e.g., "METHOD_GETPARAMETERVALUES")                  |
| ot_parent    | string  | OpenTelemetry trace parent ID (can be empty string)                  |
| ot_state     | string  | OpenTelemetry trace state (can be empty string)                      |
| offset       | int32   | **Fixed 32-bit integer** - byte offset to start of this metadata     |

**Important Notes**:

1. **Offset Field**: MUST be encoded as a **fixed 32-bit integer** (MessagePack type 0xd2), not a variable-length integer. This allows receivers to find the metadata by reading the last 4 bytes of the payload.

2. **Position**: The metadata is always appended to the end of the payload, after all request/response data.

3. **Self-Referential Offset**: The offset value points to the byte position where the method_name field begins within the payload.

**Example**:

For a payload with total length of 74 bytes where the metadata starts at byte 38:
```
[...data fields..., "METHOD_GETPARAMETERVALUES", "", "", 0xd2000000026]
                    ^                                   ^
                    metadata starts here                fixed int32 = 38
```

The offset allows fast metadata location:
```
payload_length = 74
metadata_offset_field_position = payload_length - 4  // Last 4 bytes
offset_value = read_fixed_int32(metadata_offset_field_position)  // = 38
metadata_start = offset_value  // Start reading metadata here
```

## Message Structures

### METHOD_GETPARAMETERVALUES (Request)

```
[ componentName, paramCount, parameterName, ..., method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type    | Description                           |
|-------|----------------|---------|---------------------------------------|
| 0     | componentName  | string  | Name of requesting component          |
| 1     | paramCount     | int     | Number of parameters (always 1)       |
| 2     | parameterName  | string  | Name of parameter to get              |
| 3     | method         | string  | "METHOD_GETPARAMETERVALUES"           |
| 4     | ot_parent      | string  | OpenTelemetry parent (can be empty)   |
| 5     | ot_state       | string  | OpenTelemetry state (can be empty)    |
| 6     | offset         | int32   | Offset to metadata (fixed 32-bit)     |

### METHOD_SETPARAMETERVALUES (Request)

```
[ sessionId, componentName, rollback, paramCount, [name, type, value]×N, commit, method, ot_parent, ot_state, offset ]
```

| Index    | Field          | Type    | Description                                   |
|----------|----------------|---------|-----------------------------------------------|
| 0        | sessionId      | int     | Session ID (0 for non-session operations)     |
| 1        | componentName  | string  | Name of requesting component                  |
| 2        | rollback       | int     | Rollback flag (0 or 1)                        |
| 3        | paramCount     | int     | Number of parameters to set                   |
| 4+3×i    | paramName      | string  | Parameter name (for each parameter i)         |
| 5+3×i    | paramType      | int     | RBus type ID (0x500-0x512)                    |
| 6+3×i    | paramValue     | varies  | Parameter value (type depends on paramType)   |
| 4+3×N    | commit         | string  | "TRUE" or "FALSE" - commit flag               |
| 5+3×N    | method         | string  | "METHOD_SETPARAMETERVALUES"                   |
| 6+3×N    | ot_parent      | string  | OpenTelemetry parent (can be empty)           |
| 7+3×N    | ot_state       | string  | OpenTelemetry state (can be empty)            |
| 8+3×N    | offset         | int32   | Offset to metadata (fixed 32-bit)             |

**Example with 1 parameter**:
```
[0, "rbuscli-66274", 0, 1, "Device.Test.Property", 0x50E, "test", "TRUE", "METHOD_SETPARAMETERVALUES", "", "", 38]
```

### METHOD_RESPONSE (Response)

The response structure depends on whether the operation succeeded or failed.

**For successful SET response**:
```
[ errorCode, [propertyName, propertyType, propertyValue]×N, method, ot_parent, ot_state, offset ]
```

| Index    | Field          | Type    | Description                                   |
|----------|----------------|---------|-----------------------------------------------|
| 0        | errorCode      | int     | rbusError_t result (RBUS_ERROR_SUCCESS)       |
| 1+3×i    | propertyName   | string  | Property name that was set (cached value)     |
| 2+3×i    | propertyType   | int     | RBus type ID (0x500-0x512)                    |
| 3+3×i    | propertyValue  | varies  | Property value (cached from before set)       |
| 1+3×N    | method         | string  | "METHOD_RESPONSE"                             |
| 2+3×N    | ot_parent      | string  | OpenTelemetry parent                          |
| 3+3×N    | ot_state       | string  | OpenTelemetry state                           |
| 4+3×N    | offset         | int32   | Fixed 0xd2 format, self-referential pointer   |

**For failed SET response**:
```
[ errorCode, failedElementName, method, ot_parent, ot_state, offset ]
```

| Index | Field             | Type    | Description                                   |
|-------|-------------------|---------|-----------------------------------------------|
| 0     | errorCode         | int     | rbusError_t error code (!= SUCCESS)           |
| 1     | failedElementName | string  | Name of parameter that caused failure         |
| 2     | method            | string  | "METHOD_RESPONSE"                             |
| 3     | ot_parent         | string  | OpenTelemetry parent                          |
| 4     | ot_state          | string  | OpenTelemetry state                           |
| 5     | offset            | int32   | Fixed 0xd2 format, self-referential pointer   |

**Notes**:
- The `errorCode` field (index 0) is the return value from the provider's set handler
- For successful SET, cached property values are returned for rollback support
- For failed SET, only the failed element name is returned (no property data)
- The metadata (method, ot_parent, ot_state, offset) is added automatically by the core layer
- Source: `/rbus/src/rbus/rbus.c` lines 1658-1668 (_set_callback_handler)

**For GET response**:
```
[ errorCode, propertyCount, [propertyName, propertyType, propertyValue]×N, method, ot_parent, ot_state, offset ]
```

| Index    | Field          | Type    | Description                                   |
|----------|----------------|---------|-----------------------------------------------|
| 0        | errorCode      | int     | rbusError_t result from handler               |
| 1        | propertyCount  | int     | Number of properties returned                 |
| 2+3×i    | propertyName   | string  | Property name (for each property i)           |
| 3+3×i    | propertyType   | int     | RBus type ID (0x500-0x512)                    |
| 4+3×i    | propertyValue  | varies  | Property value                                |
| 2+3×N    | method         | string  | "METHOD_RESPONSE"                             |
| 3+3×N    | ot_parent      | string  | OpenTelemetry parent                          |
| 4+3×N    | ot_state       | string  | OpenTelemetry state                           |
| 5+3×N    | offset         | int32   | Fixed 0xd2 format, self-referential pointer   |

**Notes**:
- The `errorCode` field (index 0) is the return value from the provider's get handler
- If errorCode != RBUS_ERROR_SUCCESS, propertyCount and properties are omitted
- For successful GET with single property: `[errorCode, 1, name, type, value, metadata...]`
- For successful GET with no matches: `[errorCode, 0, metadata...]`
- The metadata (method, ot_parent, ot_state, offset) is added automatically by the core layer
- Source: `/rbus/src/rbus/rbus.c` lines 2091-2120 (_get_callback_handler)

### METHOD_COMMIT (Request)

```
[ sessionId, componentName, paramCount, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type    | Description                                   |
|-------|----------------|---------|-----------------------------------------------|
| 0     | sessionId      | int     | Session ID to commit                          |
| 1     | componentName  | string  | Name of requesting component                  |
| 2     | paramCount     | int     | Number of parameters in session (usually 1)   |
| 3     | method         | string  | "METHOD_COMMIT"                               |
| 4     | ot_parent      | string  | OpenTelemetry parent                          |
| 5     | ot_state       | string  | OpenTelemetry state                           |
| 6     | offset         | int32   | Offset to metadata                            |

### METHOD_RPC / Invoke Operation (Request)

Remote method invocation allows executing provider-defined methods with optional parameters.

**Message Structure** (MessagePack-encoded):
```
[ sessionId, methodName, hasParams, params, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type                          | Description                                   |
|-------|----------------|-------------------------------|-----------------------------------------------|
| 0     | sessionId      | int                           | Session identifier (reserved, 0)              |
| 1     | methodName     | string                        | Name of method to invoke                      |
| 2     | hasParams      | int                           | 1 if params present, 0 otherwise              |
| 3     | params         | MessagePack RBusObject        | Input parameters (if hasParams = 1)           |
| 4     | method         | string                        | "METHOD_RPC"                                  |
| 5     | ot_parent      | string                        | OpenTelemetry parent                          |
| 6     | ot_state       | string                        | OpenTelemetry state                           |
| 7     | offset         | int32                         | Offset to metadata (fixed 32-bit)             |

**Response** (Success):
```
[ status, result, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type                          | Description                                   |
|-------|----------------|-------------------------------|-----------------------------------------------|
| 0     | status         | int                           | Result status (0 or 100 = success)            |
| 1     | result         | MessagePack RBusObject        | Output result object                          |
| 2     | method         | string                        | "METHOD_RESPONSE"                             |
| 3     | ot_parent      | string                        | OpenTelemetry parent                          |
| 4     | ot_state       | string                        | OpenTelemetry state                           |
| 5     | offset         | int32                         | Offset to metadata                            |

**Response** (Error):
```
[ status, method, ot_parent, ot_state, offset ]
```

### METHOD_SUBSCRIBE (Request)

Subscribe to property change events or value-change notifications.

**Message Structure** (MessagePack-encoded):
```
[ eventName, replyTopic, hasPayload, payload, publishOnSubscribe, rawDataSubscription, method, ot_parent, ot_state, offset ]
```

| Index | Field                | Type                    | Description                                             |
|-------|----------------------|-------------------------|---------------------------------------------------------|
| 0     | eventName            | string                  | Event/property name to monitor                          |
| 1     | replyTopic           | string                  | Topic where events should be sent                       |
| 2     | hasPayload           | int                     | Always 1 (payload present)                              |
| 3     | payload              | MessagePack binary      | Subscription parameters (see below)                     |
| 4     | publishOnSubscribe   | int                     | Send immediate event on subscribe (0=no, 1=yes)         |
| 5     | rawDataSubscription  | int                     | Raw data mode (0=normal, 1=raw)                         |
| 6     | method               | string                  | "METHOD_SUBSCRIBE"                                      |
| 7     | ot_parent            | string                  | OpenTelemetry parent                                    |
| 8     | ot_state             | string                  | OpenTelemetry state                                     |
| 9     | offset               | int32                   | Offset to metadata (fixed 32-bit)                       |

**Payload Fields** (MessagePack-encoded within binary payload):

| Field        | Type    | Description                                          |
|--------------|---------|------------------------------------------------------|
| componentId  | int     | Component identifier (reserved, 0)                   |
| interval     | int     | Polling interval in ms (0=change-based)              |
| duration     | int     | Subscription duration (0=indefinite)                 |
| hasFilter    | int     | Filter present flag (0=no filter)                    |

**Response**:
```
[ status, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type    | Description                                   |
|-------|----------------|---------|-----------------------------------------------|
| 0     | status         | int     | Result status (0=success)                     |
| 1     | method         | string  | "METHOD_RESPONSE"                             |
| 2     | ot_parent      | string  | OpenTelemetry parent                          |
| 3     | ot_state       | string  | OpenTelemetry state                           |
| 4     | offset         | int32   | Offset to metadata                            |

### METHOD_GETPARAMETERNAMES / Discovery (Request)

Enumerate elements in the data model tree.

**Message Structure** (MessagePack-encoded):
```
[ objectName, depth, getRowNamesOnly, method, ot_parent, ot_state, offset ]
```

| Index | Field            | Type    | Description                                             |
|-------|------------------|---------|---------------------------------------------------------|
| 0     | objectName       | string  | Root object for discovery (e.g., "Device.WiFi.")        |
| 1     | depth            | int     | Recursion depth (0=single level, -1=unlimited)          |
| 2     | getRowNamesOnly  | int     | 1=table rows only, 0=all elements                       |
| 3     | method           | string  | "METHOD_GETPARAMETERNAMES"                              |
| 4     | ot_parent        | string  | OpenTelemetry parent                                    |
| 5     | ot_state         | string  | OpenTelemetry state                                     |
| 6     | offset           | int32   | Offset to metadata                                      |

**Note**: When `getRowNamesOnly=1`, the operation returns only table row instance numbers and aliases.

**Response** (All Elements):
```
[ status, count, [name, type, access]×N, method, ot_parent, ot_state, offset ]
```

| Index  | Field          | Type    | Description                                             |
|--------|----------------|---------|---------------------------------------------------------|
| 0      | status         | int     | Result status (0=success)                               |
| 1      | count          | int     | Number of elements found                                |
| 2+3×i  | name           | string  | Full path of element (e.g., "Device.WiFi.SSID")         |
| 3+3×i  | type           | int     | Element type (see below)                                |
| 4+3×i  | access         | int     | Access permissions (read/write flags)                   |
| 2+3×N  | method         | string  | "METHOD_RESPONSE"                                       |
| 3+3×N  | ot_parent      | string  | OpenTelemetry parent                                    |
| 4+3×N  | ot_state       | string  | OpenTelemetry state                                     |
| 5+3×N  | offset         | int32   | Offset to metadata                                      |

**Element Types** (rbusElementType_t):

| Code | Name                       | Description              |
|------|----------------------------|--------------------------|
| 0    | RBUS_ELEMENT_TYPE_PROPERTY | Leaf property value      |
| 1    | RBUS_ELEMENT_TYPE_TABLE    | Multi-instance table     |
| 2    | RBUS_ELEMENT_TYPE_EVENT    | Event source             |
| 3    | RBUS_ELEMENT_TYPE_METHOD   | Invocable method         |

**Access Flags**:

| Bit  | Name  | Description              |
|------|-------|--------------------------|
| 0x01 | Read  | Property can be read     |
| 0x02 | Write | Property can be written  |

**Response** (Row Names Only - when getRowNamesOnly=1):
```
[ status, count, [instanceNumber, alias]×N, method, ot_parent, ot_state, offset ]
```

### Table Operations

Table operations allow dynamic creation and deletion of table rows in the data model. Tables represent multi-instance objects (e.g., "Device.WiFi.AccessPoint.{i}").

#### Add Table Row (METHOD_ADDTBLROW)

**Request**:
```
[ sessionId, tableName, aliasName, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type    | Description                                             |
|-------|----------------|---------|---------------------------------------------------------|
| 0     | sessionId      | int     | Session identifier (reserved, 0)                        |
| 1     | tableName      | string  | Name of table (e.g., "Device.WiFi.AccessPoint.")        |
| 2     | aliasName      | string  | Optional alias for new row (empty string if not used)   |
| 3     | method         | string  | "METHOD_ADDTBLROW"                                      |
| 4     | ot_parent      | string  | OpenTelemetry parent                                    |
| 5     | ot_state       | string  | OpenTelemetry state                                     |
| 6     | offset         | int32   | Offset to metadata                                      |

**Note**: The `tableName` MUST end with a period (e.g., "Device.WiFi.AccessPoint.").

**Response**:
```
[ status, instanceNumber, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type    | Description                                   |
|-------|----------------|---------|-----------------------------------------------|
| 0     | status         | int     | Result status (0=success)                     |
| 1     | instanceNumber | int     | Assigned instance number for new row          |
| 2     | method         | string  | "METHOD_RESPONSE"                             |
| 3     | ot_parent      | string  | OpenTelemetry parent                          |
| 4     | ot_state       | string  | OpenTelemetry state                           |
| 5     | offset         | int32   | Offset to metadata                            |

**Instance Numbering**:
- Providers assign unique instance numbers to each row
- Instance numbers SHOULD be monotonically increasing
- Rows can be accessed by instance number: "Device.WiFi.AccessPoint.1"
- Rows can also be accessed by alias if provided: "Device.WiFi.AccessPoint.[home_network]"

#### Remove Table Row (METHOD_DELETETBLROW)

**Request**:
```
[ sessionId, rowName, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type    | Description                                             |
|-------|----------------|---------|---------------------------------------------------------|
| 0     | sessionId      | int     | Session identifier (reserved, 0)                        |
| 1     | rowName        | string  | Fully qualified row name                                |
| 2     | method         | string  | "METHOD_DELETETBLROW"                                   |
| 3     | ot_parent      | string  | OpenTelemetry parent                                    |
| 4     | ot_state       | string  | OpenTelemetry state                                     |
| 5     | offset         | int32   | Offset to metadata                                      |

**Row Naming Formats**:
- By instance number: "Device.WiFi.AccessPoint.1"
- By alias: "Device.WiFi.AccessPoint.[home_network]"

**Response**:
```
[ status, method, ot_parent, ot_state, offset ]
```

| Index | Field          | Type    | Description                                   |
|-------|----------------|---------|-----------------------------------------------|
| 0     | status         | int     | Result status (0=success)                     |
| 1     | method         | string  | "METHOD_RESPONSE"                             |
| 2     | ot_parent      | string  | OpenTelemetry parent                          |
| 3     | ot_state       | string  | OpenTelemetry state                           |
| 4     | offset         | int32   | Offset to metadata                            |

### Event Messages

Events are published to subscribers when values change or events occur.

**IMPORTANT**: Event messages use a **different metadata structure** than other RBus messages.

**Message Structure** (MessagePack-encoded):
```
[ eventName, eventType, hasData, data, hasFilter, interval, duration, componentId, eventMetadata ]
```

| Index | Field          | Type                          | Description                                   |
|-------|----------------|-------------------------------|-----------------------------------------------|
| 0     | eventName      | string                        | Name of the event being published             |
| 1     | eventType      | int                           | Event type (3 = general event)                |
| 2     | hasData        | int                           | 1 if event data present, 0 otherwise          |
| 3     | data           | MessagePack RBusObject        | Event data payload (if hasData = 1)           |
| 4     | hasFilter      | int                           | Filter applied flag (reserved, 0)             |
| 5     | interval       | int                           | Event interval (reserved, 0)                  |
| 6     | duration       | int                           | Event duration (reserved, 0)                  |
| 7     | componentId    | int                           | Publishing component ID                       |
| N-4   | eventName2     | string                        | Event name (repeated from metadata)           |
| N-3   | objectName     | string                        | Publishing component name                     |
| N-2   | isRbus2        | int                           | RBus version flag (always 1)                  |
| N-1   | offset         | int32                         | Byte offset to metadata (fixed 32-bit)        |

**Event Metadata Structure** (DIFFERENT from normal metadata):
```
[ eventName, objectName, isRbus2, offset ]
```

| Field      | Type   | Description                                          |
|------------|--------|------------------------------------------------------|
| eventName  | string | Event name (matches eventName in body)               |
| objectName | string | Publishing component name                            |
| isRbus2    | int    | RBus version flag (always 1)                         |
| offset     | int32  | Byte offset to metadata (MUST use fixed 32-bit encoding 0xd2) |

**Critical Difference**: Events do NOT use the standard `[method, ot_parent, ot_state, offset]` metadata. They use the special event metadata format shown above.

## Data Type Encoding

All RBus data types use MessagePack encoding with specific conventions.

### String Encoding

Strings are encoded as MessagePack strings (fixstr, str8, str16, or str32).

**Encoding**:
1. Write MessagePack string header
2. Write UTF-8 bytes
3. No null terminator in MessagePack

**Wire Format**:
```
[MessagePack Str Header][UTF-8 Bytes]
```

### RBusValue Encoding

RBus values use a two-part encoding: type ID followed by value.

#### Type Encoding Rules

**Binary Encoding Types**: The following types encode their value as MessagePack binary (not integer):
- None, Boolean, Char, Int8, UInt8, String, Bytes

**Integer Encoding**: Int16 through UInt32 use MessagePack variable-length integer encoding.

**Fixed-Width Encoding**: Int64 and UInt64 MUST use MessagePack fixed 64-bit encoding (0xd3).

**Float Encoding**: Single values are promoted to double-precision for encoding.

**String Termination**: String type (0x50E) includes a null terminator byte after the UTF-8 data.

#### Encoding Examples

**Boolean True**:
```
[MessagePack Int: 0x500][MessagePack Bin8: 0xc4 0x01 0x01]
                                          │   │   │
                                          │   │   └─ value: 0x01 (true)
                                          │   └───── length: 1
                                          └───────── bin8 marker
```

**Int32 Value 42**:
```
[MessagePack Int: 0x507][MessagePack Int: 42]
```

**String "hello"**:
```
[MessagePack Int: 0x50E][MessagePack Bin8: 0xc4 0x06 'h' 'e' 'l' 'l' 'o' 0x00]
                                          │   │    └─────┬─────┘ │
                                          │   │          │       └─ null terminator
                                          │   └────────── length: 6
                                          └────────────── bin8 marker
```

### RBusProperty Encoding

A property is a name-value pair.

**MessagePack Encoding**:
```
┌─────────────────────────────────────┐
│  name (MessagePack string)          │
├─────────────────────────────────────┤
│  value (MessagePack-encoded RBusValue)│
└─────────────────────────────────────┘
```

**Example**:
```
Property: name="temperature", value=Int32(25)

MessagePack wire bytes:
[MessagePack Str: "temperature"][Type ID: 0x507][MessagePack Int: 25]
```

### RBusObject Encoding

An object is a named collection of properties.

**MessagePack Encoding**:
```
┌─────────────────────────────────────┐
│  name (MessagePack string)          │
├─────────────────────────────────────┤
│  object_type (MessagePack int) = 0  │
├─────────────────────────────────────┤
│  property_count (MessagePack int)   │
├─────────────────────────────────────┤
│  properties (MessagePack RBusProperty[])│
├─────────────────────────────────────┤
│  children_count (MessagePack int) = 0│
└─────────────────────────────────────┘
```

**Field Descriptions**:

| Field          | Type                  | Description                              |
|----------------|-----------------------|------------------------------------------|
| name           | MessagePack string    | Object name identifier                   |
| object_type    | MessagePack integer   | Object type (0=single instance)          |
| property_count | MessagePack integer   | Number of properties that follow         |
| properties     | MessagePack array     | MessagePack-encoded RBusProperty elements |
| children_count | MessagePack integer   | Number of child objects (always 0)       |

**Example**:
```
Object: name="ThermostatData"
  properties:
    - name="temperature", value=Int32(25)
    - name="humidity", value=Int32(60)

MessagePack wire bytes:
[MessagePack Str: "ThermostatData"]
[MessagePack Int: 0]                    // object_type
[MessagePack Int: 2]                    // property_count
  [MessagePack Str: "temperature"][Type: 0x507][MessagePack Int: 25]
  [MessagePack Str: "humidity"][Type: 0x507][MessagePack Int: 60]
[MessagePack Int: 0]                    // children_count
```

## Security Considerations

### Access Control

- Socket permissions on `/tmp/rtrouted` control access
- No built-in authentication mechanism
- Relies on Unix file permissions for security

### Data Validation

Implementations MUST validate:
- Header markers (both 0xAAAA) and version (2)
- Field lengths against maximum limits
- MessagePack structure integrity
- UTF-8 string encoding validity

### Resource Limits

To prevent denial-of-service:
- Topic length ≤ 256 bytes
- Reply topic length ≤ 256 bytes
- Payload length should be bounded (implementation-specific)
- Message rate limiting recommended

### Encryption

The Encrypted flag (0x20) is defined but:
- Encryption format is implementation-specific
- No standard encryption scheme defined
- End-to-end encryption must be implemented separately

## Appendix

### Compliance Checklist

Implementations MUST:
- ✓ Validate both 0xAAAA header markers
- ✓ Use version 2 in all messages
- ✓ Encode all integers in big-endian
- ✓ Set RawBinary flag for MessagePack payloads
- ✓ Encode metadata offset as fixed 32-bit integer (0xd2)
- ✓ Include null terminator in String type (0x50E) values
- ✓ Validate topic lengths ≤ 256 bytes
- ✓ Support all defined RBusValue types (including CCSP types)
- ✓ Handle both status codes 0 and 100 as success

Implementations SHOULD:
- Implement connection retry logic
- Rate-limit message sending
- Validate MessagePack structure
- Log malformed messages for debugging
- Implement graceful shutdown
- Clean up subscriptions on disconnect

### MessagePack Quick Reference

| Type     | Format Byte     | Description                  |
|----------|-----------------|------------------------------|
| fixint   | 0x00-0x7f       | Positive integer 0-127       |
| fixstr   | 0xa0-0xbf       | String length 0-31           |
| nil      | 0xc0            | Null value                   |
| false    | 0xc2            | Boolean false                |
| true     | 0xc3            | Boolean true                 |
| bin8     | 0xc4            | Binary, 1-byte length        |
| bin16    | 0xc5            | Binary, 2-byte length        |
| bin32    | 0xc6            | Binary, 4-byte length        |
| float64  | 0xcb            | 64-bit IEEE 754 float        |
| uint8    | 0xcc            | 8-bit unsigned               |
| uint16   | 0xcd            | 16-bit unsigned              |
| uint32   | 0xce            | 32-bit unsigned              |
| int8     | 0xd0            | 8-bit signed                 |
| int16    | 0xd1            | 16-bit signed                |
| int32    | 0xd2            | 32-bit signed                |
| int64    | 0xd3            | 64-bit signed                |
| str8     | 0xd9            | String, 1-byte length        |
| str16    | 0xda            | String, 2-byte length        |
| str32    | 0xdb            | String, 4-byte length        |

## Error Codes

### rbusError_t (High-level API errors)

| Code | Name                                        | Value | Description                                       |
|------|---------------------------------------------|-------|---------------------------------------------------|
| 0    | RBUS_ERROR_SUCCESS                          | 0     | Success                                           |
| 1    | RBUS_ERROR_BUS_ERROR                        | 1     | General bus error                                 |
| 2    | RBUS_ERROR_INVALID_INPUT                    | 2     | Invalid input parameter                           |
| 3    | RBUS_ERROR_NOT_INITIALIZED                  | 3     | Bus not initialized                               |
| 4    | RBUS_ERROR_OUT_OF_RESOURCES                 | 4     | Running out of resources                          |
| 5    | RBUS_ERROR_DESTINATION_NOT_FOUND            | 5     | Destination element not found                     |
| 6    | RBUS_ERROR_DESTINATION_NOT_REACHABLE        | 6     | Destination element not reachable                 |
| 7    | RBUS_ERROR_DESTINATION_RESPONSE_FAILURE     | 7     | Destination failed to respond                     |
| 8    | RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION| 8     | Invalid destination response                      |
| 9    | RBUS_ERROR_INVALID_OPERATION                | 9     | Invalid operation                                 |
| 10   | RBUS_ERROR_INVALID_EVENT                    | 10    | Invalid event                                     |
| 11   | RBUS_ERROR_INVALID_HANDLE                   | 11    | Invalid handle                                    |
| 12   | RBUS_ERROR_SESSION_ALREADY_EXIST            | 12    | Session already opened                            |
| 13   | RBUS_ERROR_COMPONENT_NAME_DUPLICATE         | 13    | Component name already exists                     |
| 14   | RBUS_ERROR_ELEMENT_NAME_DUPLICATE           | 14    | Element name(s) previously registered             |
| 15   | RBUS_ERROR_ELEMENT_NAME_MISSING             | 15    | No names provided in name field                   |
| 16   | RBUS_ERROR_COMPONENT_DOES_NOT_EXIST         | 16    | Component connection not opened                   |
| 17   | RBUS_ERROR_ELEMENT_DOES_NOT_EXIST           | 17    | Element name(s) don't have valid registration     |
| 18   | RBUS_ERROR_ACCESS_NOT_ALLOWED               | 18    | Access not permitted by provider                  |
| 19   | RBUS_ERROR_INVALID_CONTEXT                  | 19    | Context doesn't match callback handler            |
| 20   | RBUS_ERROR_TIMEOUT                          | 20    | Operation timed out                               |
| 21   | RBUS_ERROR_ASYNC_RESPONSE                   | 21    | Method request handled asynchronously             |
| 22   | RBUS_ERROR_INVALID_METHOD                   | 22    | Invalid method                                    |
| 23   | RBUS_ERROR_NOSUBSCRIBERS                    | 23    | No subscribers present                            |
| 24   | RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST       | 24    | Subscription already exists                       |
| 25   | RBUS_ERROR_INVALID_NAMESPACE                | 25    | Invalid namespace per standard                    |
| 26   | RBUS_ERROR_DIRECT_CON_NOT_EXIST             | 26    | Direct connection doesn't exist                   |
| 27   | RBUS_ERROR_NOT_WRITABLE                     | 27    | Set not permitted by provider                     |
| 28   | RBUS_ERROR_NOT_READABLE                     | 28    | Get not permitted by provider                     |
| 29   | RBUS_ERROR_INVALID_PARAMETER_TYPE           | 29    | Invalid parameter type                            |
| 30   | RBUS_ERROR_INVALID_PARAMETER_VALUE          | 30    | Invalid parameter value                           |

### rbusCoreError_t (Core transport layer errors)

| Code | Name                                        | Value | Description                                       |
|------|---------------------------------------------|-------|---------------------------------------------------|
| 0    | RBUSCORE_SUCCESS                            | 0     | Success                                           |
| 1    | RBUSCORE_ERROR_GENERAL                      | 1     | General error                                     |
| 2    | RBUSCORE_ERROR_INVALID_PARAM                | 2     | Invalid parameter                                 |
| 3    | RBUSCORE_ERROR_INSUFFICIENT_MEMORY          | 3     | Insufficient memory                               |
| 4    | RBUSCORE_ERROR_INVALID_STATE                | 4     | Invalid state                                     |
| 5    | RBUSCORE_ERROR_REMOTE_END_DECLINED_TO_RESPOND| 5    | Remote end declined to respond                    |
| 6    | RBUSCORE_ERROR_REMOTE_END_FAILED_TO_RESPOND | 6     | Remote end failed to respond                      |
| 7    | RBUSCORE_ERROR_REMOTE_TIMED_OUT             | 7     | Remote timed out                                  |
| 8    | RBUSCORE_ERROR_MALFORMED_RESPONSE           | 8     | Malformed response                                |
| 9    | RBUSCORE_ERROR_UNSUPPORTED_METHOD           | 9     | Unsupported method                                |
| 10   | RBUSCORE_ERROR_UNSUPPORTED_EVENT            | 10    | Unsupported event                                 |
| 11   | RBUSCORE_ERROR_OUT_OF_RESOURCES             | 11    | Out of resources                                  |
| 12   | RBUSCORE_ERROR_DESTINATION_UNREACHABLE      | 12    | Destination unreachable                           |
| 13   | RBUSCORE_SUCCESS_ASYNC                      | 13    | Success (async)                                   |
| 14   | RBUSCORE_ERROR_SUBSCRIBE_NOT_HANDLED        | 14    | Subscribe not handled                             |
| 15   | RBUSCORE_ERROR_EVENT_NOT_HANDLED            | 15    | Event not handled                                 |
| 16   | RBUSCORE_ERROR_DUPLICATE_ENTRY              | 16    | Duplicate entry                                   |
| 17   | RBUSCORE_ERROR_ENTRY_NOT_FOUND              | 17    | Entry not found                                   |
| 18   | RBUSCORE_ERROR_UNSUPPORTED_ENTRY            | 18    | Unsupported entry                                 |

## Result Code Calculation

The result/error code in METHOD_RESPONSE messages is calculated and set by the RBus handler layer:

### For GET Operations
**Source**: `/rbus/src/rbus/rbus.c` lines 2091-2120 (`_get_callback_handler`)

```c
rbusMessage_Init(response);
rbusMessage_SetInt32(*response, (int) result);  // Index 0: Error code from handler
if(properties && result == RBUS_ERROR_SUCCESS)
{
    rbusMessage_SetInt32(*response, paramSize);  // Index 1: Property count
    for(i = 0; i < paramSize; i++)
    {
        rbusValue_appendToMessage(...);  // Properties
    }
}
```

The `result` variable accumulates errors from:
1. **Element Lookup**: `retrieveInstanceElement()` - returns RBUS_ERROR_ELEMENT_DOES_NOT_EXIST if not found
2. **Handler Invocation**: `el->cbTable.getHandler(handle, property, &options)` - returns rbusError_t from provider
3. **Wildcard Resolution**: `get_recursive_wildcard_handler()` - returns aggregate errors

### For SET Operations
**Source**: `/rbus/src/rbus/rbus.c` lines 1486-1668 (`_set_callback_handler`)

```c
rbusMessage_Init(response);
rbusMessage_SetInt32(*response, (int) rc);  // Index 0: Error code
if (rc == RBUS_ERROR_SUCCESS)
{
    rbusPropertyList_appendToMessage(cachedData, *response);  // Cached values
}
else if(pFailedElement)
    rbusMessage_SetString(*response, pFailedElement);  // Failed element name
```

The `rc` variable accumulates errors from:
1. **Memory Allocation**: Returns RBUS_ERROR_OUT_OF_RESOURCES if malloc fails
2. **Element Lookup**: Returns RBUS_ERROR_ELEMENT_DOES_NOT_EXIST if not found
3. **Write Permission**: Returns RBUS_ERROR_NOT_WRITABLE if no setHandler registered
4. **Handler Invocation**: `el->cbTable.setHandler(handle, property, &opts)` - returns rbusError_t from provider
5. **Rollback Operations**: If any set fails, cached values are restored

### Custom Error Codes
- Providers can return custom error codes from their handlers
- Values outside the standard rbusError_t range (0-30) are provider-specific
- Example: "Result Code: 141" likely indicates a custom/legacy error from the provider
- Legacy CCSP components may return `rbusLegacyReturn_t` codes which are converted via `CCSPError_to_rbusError()`

### Key Points
- The result code is **always at index 0** in METHOD_RESPONSE messages
- It represents the `rbusError_t` return value from the provider's callback handler
- The core layer (`rbus_sendResponse()`) does NOT modify this code - it only adds metadata
- There is **no separate "final result code" field** - the index 0 error code IS the final result

## Sessions and Transactions

RBus supports session-based operations for atomic multi-parameter sets:

1. **Session ID**: Generated by calling `rbus_createSession()`
2. **Multiple SET operations**: Each SET uses the same sessionId with commit=FALSE
3. **Final SET or COMMIT**: Last operation has commit=TRUE
4. **Rollback**: If rollback flag is set, all session operations are rolled back

### Example Session Flow

```
1. Create Session → sessionId = 12345
2. SET param1 (sessionId=12345, commit=FALSE) → Remembered
3. SET param2 (sessionId=12345, commit=FALSE) → Remembered
4. SET param3 (sessionId=12345, commit=TRUE)  → All committed atomically
```

Or using explicit commit:

```
1. Create Session → sessionId = 12345
2. SET param1 (sessionId=12345, commit=FALSE) → Remembered
3. SET param2 (sessionId=12345, commit=FALSE) → Remembered
4. COMMIT (sessionId=12345) → All committed atomically
```

## OpenTelemetry Integration

RBus includes OpenTelemetry tracing support:

- **ot_parent**: Trace parent ID for distributed tracing
- **ot_state**: Trace state information
- These fields are always present in metadata but can be empty strings

## Control Data Field

The `control_data` field is used for routing and forwarding:

- **0**: Direct message (not forwarded)
- **Non-zero**: Forwarded message (value indicates hop count or routing info)

This affects the Info column display:
- Request (control_data=0): "Request"
- Request (control_data≠0): "Request (forwarded)"
- Response (control_data=0): "Response"
- Response (control_data≠0): "Response (forwarded)"

## Example Packet Decodes

### Example 1: GET Request

```
Header:
  Marker: 0xAAAA
  Version: 2
  Sequence: 10
  Flags: 0x11 (Request | RawBinary)
  Topic: "Device.Test.Property"
  Reply Topic: "rbus.rbuscli.INBOX.66274"

Payload (MessagePack):
  [0] "rbuscli-66274"             // Component Name
  [1] 1                            // Parameter Count
  [2] "Device.Test.Property"      // Parameter Name
  [3] "METHOD_GETPARAMETERVALUES" // Method
  [4] ""                           // OpenTelemetry Parent
  [5] ""                           // OpenTelemetry State
  [6] 38                           // Offset
```

### Example 2: GET Response

```
Header:
  Marker: 0xAAAA
  Version: 2
  Sequence: 10
  Flags: 0x12 (Response | RawBinary)
  Topic: "rbus.rbuscli.INBOX.66274"
  Reply Topic: "Device.Test.Property"

Payload (MessagePack):
  [0] 0                            // Session ID
  [1] 1                            // Error Code (success)
  [2] "Device.Test.Property"       // Property Name
  [3] 0x50E                        // Property Type (String)
  [4] "test2"                      // Property Value
  [5] "METHOD_RESPONSE"            // Method
  [6] ""                           // OpenTelemetry Parent
  [7] ""                           // OpenTelemetry State
  [8] 35                           // Result Code
```

### Example 3: SET Request

```
Header:
  Marker: 0xAAAA
  Version: 2
  Sequence: 8
  Flags: 0x11 (Request | RawBinary)
  Topic: "Device.Test.Property"
  Reply Topic: "rbus.rbuscli.INBOX.66274"

Payload (MessagePack):
  [0] 0                            // Session ID
  [1] "rbuscli-66274"              // Component Name
  [2] 0                            // Rollback
  [3] 1                            // Parameter Count
  [4] "Device.Test.Property"       // Parameter Name
  [5] 0x50E                        // Parameter Type (String)
  [6] "test"                       // Parameter Value
  [7] "TRUE"                       // Commit Flag
  [8] "METHOD_SETPARAMETERVALUES"  // Method
  [9] ""                           // OpenTelemetry Parent
  [10] ""                          // OpenTelemetry State
  [11] 38                          // Offset
```

## Notes

- **Byte Order**: All multi-byte fields in the header are big-endian (network byte order)
- **MessagePack**: The payload uses standard MessagePack encoding
- **Strings**: All strings in MessagePack are UTF-8 encoded
- **Topics**: Topic names are hierarchical dot-separated strings (e.g., "Device.WiFi.SSID")
- **Reply Topics**: Typically in format "rbus.<component>.INBOX.<pid>"
- **Offset Field**: The offset field in metadata always points to the start of the metadata structure within the payload

## References

### Official Documentation
- **RBus GitHub Repository**: [https://github.com/rdkcentral/rbus](https://github.com/rdkcentral/rbus)
- **RBus Wire Protocol Specification**: [https://github.com/cbucht200/rbus/blob/develop/docs/WireProtocol.md](https://github.com/cbucht200/rbus/blob/develop/docs/WireProtocol.md)
- **MessagePack Specification**: [https://github.com/msgpack/msgpack/blob/master/spec.md](https://github.com/msgpack/msgpack/blob/master/spec.md)
- **JSON Specification**: RFC 8259
- **Unix Domain Sockets**: POSIX.1-2001

### Source Files Analyzed
- `/rbus/src/rtmessage/rtMessageHeader.h`
- `/rbus/src/rtmessage/rtMessageHeader.c`
- `/rbus/src/core/rbuscore_types.h`
- `/rbus/include/rbus.h`
- `/rbus/include/rbus_value.h`
- `/rbus/src/rbus/rbus.c`

### Version History

| Version | Date    | Notes                                                           |
|---------|---------|----------------------------------------------------------------|
| 2.0     | 2026-02 | Updated with complete specification including control messages and data type encoding |
| 1.0     | 2026-01 | Initial specification based on source code analysis            |
