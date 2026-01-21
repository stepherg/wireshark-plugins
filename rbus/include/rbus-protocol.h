/*
 * rbus-protocol.h - RBus Protocol Structure Definitions
 *
 * Copyright 2026
 * Licensed under the Apache License, Version 2.0
 */

#ifndef RBUS_PROTOCOL_H
#define RBUS_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RBus Protocol Constants
 */
#define RBUS_PROTOCOL_NAME "rbus"
#define RBUS_PROTOCOL_SHORT_NAME "RBus"
#define RBUS_PROTOCOL_LONG_NAME "RDK Bus Protocol"

/* Default TCP port for RBus */
#define RBUS_DEFAULT_TCP_PORT 10002

/* Unix Domain Socket path */
#define RBUS_DEFAULT_UDS_PATH "/tmp/rtrouted"

/* Protocol version */
#define RBUS_PROTOCOL_VERSION 1

/* Maximum field sizes */
#define RBUS_MAX_TOPIC_LENGTH 1024
#define RBUS_MAX_PAYLOAD_SIZE (10 * 1024 * 1024) /* 10MB */

/*
 * rtMessage Header Structure
 * Based on rbus/src/rtmessage/rtMessageHeader.h
 */
typedef struct {
    uint32_t version;
    uint32_t header_length;
    uint32_t sequence_number;
    uint32_t control_data;
    uint32_t payload_length;
    uint32_t topic_length;
    uint32_t reply_topic_length;
    uint8_t  flags;
} rtmsg_header_t;

/*
 * Message flags (bit field)
 */
#define RTMSG_FLAG_REQUEST      0x01
#define RTMSG_FLAG_RESPONSE     0x02
#define RTMSG_FLAG_SUBSCRIPTION 0x04

/*
 * Control data flags
 */
#define RTMSG_CONTROL_HEARTBEAT 0x01
#define RTMSG_CONTROL_DIAG      0x02

/*
 * Special topic prefixes for system messages
 */
#define RTMSG_TOPIC_RTROUTED_PREFIX "_RTROUTED."
#define RTMSG_TOPIC_DIAG "_RTROUTED.INBOX.DIAG"
#define RTMSG_TOPIC_DISCOVERY "_RTROUTED.INBOX.QUERY"

#ifdef __cplusplus
}
#endif

#endif /* RBUS_PROTOCOL_H */
