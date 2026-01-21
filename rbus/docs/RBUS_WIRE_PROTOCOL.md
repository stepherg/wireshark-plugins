# RBus Wire Protocol Documentation

This document describes the RBus (RDK Bus) wire protocol based on analysis of the source code in `/rbus/`.

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

RBus defines these value types (starting at 0x500):

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

- Source files analyzed:
  - `/rbus/src/rtmessage/rtMessageHeader.h`
  - `/rbus/src/rtmessage/rtMessageHeader.c`
  - `/rbus/src/core/rbuscore_types.h`
  - `/rbus/include/rbus.h`
  - `/rbus/include/rbus_value.h`
  - `/rbus/src/rbus/rbus.c`
