/*
 * packet-rbus.c - Wireshark dissector for RBus (RDK Bus) protocol
 *
 * Copyright 2026
 * Licensed under the Apache License, Version 2.0
 *
 * This dissector decodes RBus messaging protocol which uses:
 * - Custom rtMessage header format
 * - MessagePack encoded payloads
 * - Unix Domain Sockets or TCP transport
 */

 /* config.h is only available when building with Wireshark source tree */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/plugins.h>
#include <msgpack.h>

#include "rbus-protocol.h"

/* Wireshark plugin version */
#define PLUGIN_VERSION "1.0.0"

/* Plugin version information - required by Wireshark */
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const char plugin_release[] = PLUGIN_VERSION;

/* Plugin type - identifies this as an epan (protocol dissector) plugin */
WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

WS_DLL_PUBLIC uint32_t
plugin_describe(void) {
   return WS_PLUGIN_DESC_DISSECTOR;
}

/* Protocol handle */
static int proto_rbus = -1;

/* Dissector handle */
static dissector_handle_t rbus_handle;

/* Header fields */
static int hf_rbus_header = -1;
static int hf_rbus_opening_marker = -1;
static int hf_rbus_version = -1;
static int hf_rbus_header_length = -1;
static int hf_rbus_sequence_number = -1;
static int hf_rbus_control_data = -1;
static int hf_rbus_payload_length = -1;
static int hf_rbus_topic_length = -1;
static int hf_rbus_topic = -1;
static int hf_rbus_reply_topic_length = -1;
static int hf_rbus_reply_topic = -1;
static int hf_rbus_roundtrip_t1 = -1;
static int hf_rbus_roundtrip_t2 = -1;
static int hf_rbus_roundtrip_t3 = -1;
static int hf_rbus_roundtrip_t4 = -1;
static int hf_rbus_roundtrip_t5 = -1;
static int hf_rbus_closing_marker = -1;
static int hf_rbus_flags = -1;
static int hf_rbus_flags_request = -1;
static int hf_rbus_flags_response = -1;
static int hf_rbus_flags_undeliverable = -1;
static int hf_rbus_flags_tainted = -1;
static int hf_rbus_flags_raw_binary = -1;
static int hf_rbus_flags_encrypted = -1;
static int hf_rbus_payload = -1;
static int hf_rbus_payload_string = -1;
static int hf_rbus_payload_int = -1;
static int hf_rbus_payload_uint = -1;
static int hf_rbus_payload_int64 = -1;
static int hf_rbus_payload_uint64 = -1;
static int hf_rbus_payload_double = -1;
static int hf_rbus_payload_boolean = -1;

/* RBus message structure fields */
static int hf_rbus_session_id = -1;
static int hf_rbus_component_name = -1;
static int hf_rbus_param_count = -1;
static int hf_rbus_property_count = -1;
static int hf_rbus_error_code = -1;
static int hf_rbus_rollback = -1;
static int hf_rbus_commit = -1;
static int hf_rbus_parameter = -1;
static int hf_rbus_parameter_name = -1;
static int hf_rbus_parameter_type = -1;
static int hf_rbus_parameter_value_string = -1;
static int hf_rbus_parameter_value_int = -1;
static int hf_rbus_parameter_value_uint = -1;
static int hf_rbus_parameter_value_int64 = -1;
static int hf_rbus_parameter_value_uint64 = -1;
static int hf_rbus_parameter_value_double = -1;
static int hf_rbus_parameter_value_boolean = -1;
static int hf_rbus_parameter_namevalue = -1;
static int hf_rbus_property = -1;
static int hf_rbus_property_name = -1;
static int hf_rbus_property_type = -1;
static int hf_rbus_property_value_string = -1;
static int hf_rbus_property_value_int = -1;
static int hf_rbus_property_value_uint = -1;
static int hf_rbus_property_value_int64 = -1;
static int hf_rbus_property_value_uint64 = -1;
static int hf_rbus_property_value_double = -1;
static int hf_rbus_property_value_boolean = -1;
static int hf_rbus_property_namevalue = -1;
static int hf_rbus_failed_element = -1;
static int hf_rbus_metadata = -1;
static int hf_rbus_method_name = -1;
static int hf_rbus_ot_parent = -1;
static int hf_rbus_ot_state = -1;
static int hf_rbus_metadata_offset = -1;
static int hf_rbus_event_name = -1;
static int hf_rbus_reply_topic_payload = -1;
static int hf_rbus_invoke_method_name = -1;
static int hf_rbus_has_params = -1;
static int hf_rbus_event_type = -1;
static int hf_rbus_has_event_data = -1;
static int hf_rbus_event_data = -1;
static int hf_rbus_has_filter = -1;
static int hf_rbus_interval = -1;
static int hf_rbus_duration = -1;
static int hf_rbus_component_id = -1;
static int hf_rbus_object_property = -1;
static int hf_rbus_object_property_name = -1;
static int hf_rbus_object_property_namevalue = -1;

/* Subtree indices */
static gint ett_rbus = -1;
static gint ett_rbus_header = -1;
static gint ett_rbus_payload = -1;
static gint ett_rbus_flags = -1;
static gint ett_rbus_parameter = -1;
static gint ett_rbus_property = -1;
static gint ett_rbus_metadata = -1;

/* RBus Event Type IDs */
static const value_string rbus_event_type_vals[] = {
    { 0, "OBJECT_CREATED" },
    { 1, "OBJECT_DELETED" },
    { 2, "VALUE_CHANGED" },
    { 3, "GENERAL" },
    { 4, "INITIAL_VALUE" },
    { 5, "INTERVAL" },
    { 6, "DURATION_COMPLETE" },
    { 0, NULL }
};

/* RBus Value Type IDs */
static const value_string rbus_type_vals[] = {
    /* CCSP/TR-181 Data Model Types (legacy, 0-5 range) */
    { 0x00, "String" },
    { 0x01, "Int" },
    { 0x02, "UnsignedInt" },
    { 0x03, "Boolean" },
    { 0x04, "DateTime" },
    { 0x05, "Base64" },
    /* RBus Native Types (0x500+ range) */
    { 0x500, "Boolean" },
    { 0x501, "Char" },
    { 0x503, "Int8" },
    { 0x504, "UInt8" },
    { 0x505, "Int16" },
    { 0x506, "UInt16" },
    { 0x507, "Int32" },
    { 0x508, "UInt32" },
    { 0x509, "Int64" },
    { 0x50A, "UInt64" },
    { 0x50B, "Single" },
    { 0x50C, "Double" },
    { 0x50E, "String" },
    { 0x50F, "Bytes" },
    { 0x512, "None" },
    { 0, NULL }
};

/* Expert info fields */
static expert_field ei_rbus_invalid_length = EI_INIT;
static expert_field ei_rbus_malformed_header = EI_INIT;
static expert_field ei_rbus_truncated_packet = EI_INIT;
static expert_field ei_rbus_msgpack_depth_exceeded = EI_INIT;

/* Preferences */
static guint32 pref_tcp_port = RBUS_DEFAULT_TCP_PORT;
static guint32 pref_msgpack_depth_limit = 16;
static guint32 pref_msgpack_object_limit = 20000;

/* Context for tracking RBus message meta information parsing */
typedef struct {
   guint object_index;          /* Current object being parsed */
   gboolean seen_method;        /* Have we seen a METHOD_* string? */
   guint meta_field_count;      /* Count of meta fields after METHOD_* */
   const gchar* method_name;    /* The method name we detected */
   guint params_count;          /* For SET: number of parameters */
   guint params_seen;           /* For SET: number of parameter fields seen (each param = 3 fields) */
} rbus_parse_context_t;

/*
 * Helper to add a property/parameter value with the appropriate type
 * Returns a string representation of the value for namevalue field
 */
 static gchar* add_typed_value(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, guint offset,
   const msgpack_object* value_obj, gboolean is_property) {
   /* Select appropriate header fields based on whether this is a property or parameter */
   int hf_string = is_property ? hf_rbus_property_value_string : hf_rbus_parameter_value_string;
   int hf_int = is_property ? hf_rbus_property_value_int : hf_rbus_parameter_value_int;
   int hf_uint = is_property ? hf_rbus_property_value_uint : hf_rbus_parameter_value_uint;
   int hf_int64 = is_property ? hf_rbus_property_value_int64 : hf_rbus_parameter_value_int64;
   int hf_uint64 = is_property ? hf_rbus_property_value_uint64 : hf_rbus_parameter_value_uint64;
   int hf_double = is_property ? hf_rbus_property_value_double : hf_rbus_parameter_value_double;
   int hf_boolean = is_property ? hf_rbus_property_value_boolean : hf_rbus_parameter_value_boolean;

   gchar* value_str = NULL;

   /* Handle different MessagePack value types */
   switch (value_obj->type) {
      case MSGPACK_OBJECT_STR: {
         gchar* str = (gchar*)wmem_alloc(pinfo->pool, value_obj->via.str.size + 1);
         memcpy(str, value_obj->via.str.ptr, value_obj->via.str.size);
         str[value_obj->via.str.size] = '\0';
         proto_tree_add_string(tree, hf_string, tvb, offset, 1, str);
         value_str = str;
         break;
      }
      case MSGPACK_OBJECT_BIN: {
         /* Check if it's a boolean (RBus Boolean encoding) */
         if (value_obj->via.bin.size == 1) {
            guint8 byte = ((const guint8*)value_obj->via.bin.ptr)[0];
            if (byte == 0x00 || byte == 0x01) {
               proto_tree_add_boolean(tree, hf_boolean, tvb, offset, 1, byte);
               value_str = wmem_strdup(pinfo->pool, byte ? "true" : "false");
               break;
            }
         }
         /* Otherwise treat as string if it looks like UTF-8 */
         gchar* str = (gchar*)wmem_alloc(pinfo->pool, value_obj->via.bin.size + 1);
         memcpy(str, value_obj->via.bin.ptr, value_obj->via.bin.size);
         str[value_obj->via.bin.size] = '\0';
         proto_tree_add_string(tree, hf_string, tvb, offset, 1, str);
         value_str = str;
         break;
      }
      case MSGPACK_OBJECT_POSITIVE_INTEGER:
         if (value_obj->via.u64 <= G_MAXUINT32) {
            proto_tree_add_uint(tree, hf_uint, tvb, offset, 1, (guint32)value_obj->via.u64);
            value_str = wmem_strdup_printf(pinfo->pool, "%u", (guint32)value_obj->via.u64);
         } else {
            proto_tree_add_uint64(tree, hf_uint64, tvb, offset, 1, value_obj->via.u64);
            value_str = wmem_strdup_printf(pinfo->pool, "%" PRIu64, value_obj->via.u64);
         }
         break;
      case MSGPACK_OBJECT_NEGATIVE_INTEGER:
         if (value_obj->via.i64 >= G_MININT32 && value_obj->via.i64 <= G_MAXINT32) {
            proto_tree_add_int(tree, hf_int, tvb, offset, 1, (gint32)value_obj->via.i64);
            value_str = wmem_strdup_printf(pinfo->pool, "%d", (gint32)value_obj->via.i64);
         } else {
            proto_tree_add_int64(tree, hf_int64, tvb, offset, 1, value_obj->via.i64);
            value_str = wmem_strdup_printf(pinfo->pool, "%" PRId64, value_obj->via.i64);
         }
         break;
      case MSGPACK_OBJECT_FLOAT32:
      case MSGPACK_OBJECT_FLOAT64:
         proto_tree_add_double(tree, hf_double, tvb, offset, 1, value_obj->via.f64);
         value_str = wmem_strdup_printf(pinfo->pool, "%f", value_obj->via.f64);
         break;
      case MSGPACK_OBJECT_BOOLEAN:
         proto_tree_add_boolean(tree, hf_boolean, tvb, offset, 1, value_obj->via.boolean);
         value_str = wmem_strdup(pinfo->pool, value_obj->via.boolean ? "true" : "false");
         break;
      default:
         proto_tree_add_bytes_format(tree, hf_rbus_payload, tvb, offset, 1,
            NULL, "Value: [Unsupported type]");
         value_str = wmem_strdup(pinfo->pool, "[unsupported]");
         break;
   }

   return value_str;
}

/*
 * Helper to display a parsed msgpack_object recursively
 */
static void
display_msgpack_object(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo,
   guint offset, guint length, const msgpack_object* obj,
   guint depth, const char* label, rbus_parse_context_t* ctx) {
   if (depth > pref_msgpack_depth_limit) {
      proto_tree_add_expert_format(tree, pinfo, &ei_rbus_msgpack_depth_exceeded, tvb, offset, length,
         "MessagePack depth limit (%u) exceeded; further nesting not displayed", pref_msgpack_depth_limit);
      return;
   }

   proto_item* item = NULL;

   switch (obj->type) {
      case MSGPACK_OBJECT_NIL:
         if (label) {
            proto_tree_add_bytes_format(tree, hf_rbus_payload, tvb, offset, length,
               NULL, "%s: null", label);
         } else {
            proto_tree_add_bytes_format_value(tree, hf_rbus_payload, tvb, offset, length,
               NULL, "null");
         }
         break;

      case MSGPACK_OBJECT_BOOLEAN:
         if (label) {
            proto_tree_add_boolean_format(tree, hf_rbus_payload_boolean, tvb, offset, length,
               obj->via.boolean, "%s: %s", label, obj->via.boolean ? "true" : "false");
         } else {
            proto_tree_add_boolean_format_value(tree, hf_rbus_payload_boolean, tvb, offset, length,
               obj->via.boolean, "%s", obj->via.boolean ? "true" : "false");
         }
         break;

      case MSGPACK_OBJECT_POSITIVE_INTEGER: {
         /* Provide field labels for integers based on position */
         const char* field_label = label;

         /* After method is known, provide method-specific labels */
         if (ctx && ctx->method_name) {
            if (strcmp(ctx->method_name, "METHOD_SETPARAMETERVALUES") == 0) {
               /* SET request structure: sessionId(0), componentName(1), rollback(2), paramCount(3), params..., commit, method, ot, offset */
               if (ctx->object_index == 0) {
                  field_label = "Session ID";
               } else if (ctx->object_index == 2) {
                  field_label = "Rollback";
               } else if (ctx->object_index == 3) {
                  field_label = "Parameter Count";
                  ctx->params_count = (guint)obj->via.u64;
               } else if (ctx->params_count > 0 && ctx->params_seen < ctx->params_count * 3) {
                  ctx->params_seen++;
               } else if (ctx->meta_field_count >= 2) {
                  field_label = "Metadata Offset";
               }
            } else if (strcmp(ctx->method_name, "METHOD_GETPARAMETERVALUES") == 0) {
               /* GET request structure: componentName(0), paramCount(1), paramNames..., method, ot, offset */
               if (ctx->object_index == 1) {
                  field_label = "Parameter Count";
               } else if (ctx->meta_field_count >= 2) {
                  field_label = "Metadata Offset";
               }
            } else if (strcmp(ctx->method_name, "METHOD_RESPONSE") == 0) {
               /* Response structure: errorCode(0), propertyCount(1), properties..., method, ot_parent, ot_state, offset */
               if (ctx->object_index == 0) {
                  field_label = "Error Code";
               } else if (ctx->object_index == 1) {
                  field_label = "Property Count";
                  ctx->params_count = (guint)obj->via.u64;
               } else if (ctx->params_count > 0 && ctx->params_seen < ctx->params_count * 3) {
                  ctx->params_seen++;
               } else if (ctx->meta_field_count >= 2) {
                  field_label = "Metadata Offset";
               }
            } else if (ctx->meta_field_count >= 2) {
               /* Default: integer after metadata is offset field */
               field_label = "Metadata Offset";
            }
         } else if (ctx && !ctx->seen_method && ctx->object_index == 0) {
            /* Before method is known, index 0 could be Session ID or Error Code */
            field_label = "Session ID / Error Code";
         }

         /* Check if this integer is an RBus type ID */
         const gchar* type_name = try_val_to_str((guint32)obj->via.u64, rbus_type_vals);
         if (type_name) {
            /* Display as RBus type */
            if (field_label) {
               proto_tree_add_bytes_format(tree, hf_rbus_payload, tvb, offset, length,
                  NULL, "%s: %s (0x%x)", field_label, type_name, (guint32)obj->via.u64);
            } else {
               proto_tree_add_bytes_format_value(tree, hf_rbus_payload, tvb, offset, length,
                  NULL, "%s (0x%x)", type_name, (guint32)obj->via.u64);
            }
         } else {
            /* Display as regular integer */
            if (field_label) {
               proto_tree_add_uint64_format(tree, hf_rbus_payload_uint64, tvb, offset, length,
                  obj->via.u64, "%s: %" PRIu64, field_label, obj->via.u64);
            } else {
               proto_tree_add_uint64_format_value(tree, hf_rbus_payload_uint64, tvb, offset, length,
                  obj->via.u64, "%" PRIu64, obj->via.u64);
            }
         }
         break;
      }

      case MSGPACK_OBJECT_NEGATIVE_INTEGER:
         if (label) {
            proto_tree_add_int64_format(tree, hf_rbus_payload_int64, tvb, offset, length,
               obj->via.i64, "%s: %" PRId64, label, obj->via.i64);
         } else {
            proto_tree_add_int64_format_value(tree, hf_rbus_payload_int64, tvb, offset, length,
               obj->via.i64, "%" PRId64, obj->via.i64);
         }
         break;

      case MSGPACK_OBJECT_FLOAT32:
      case MSGPACK_OBJECT_FLOAT64:
         if (label) {
            proto_tree_add_double_format(tree, hf_rbus_payload_double, tvb, offset, length,
               obj->via.f64, "%s: %f", label, obj->via.f64);
         } else {
            proto_tree_add_double_format_value(tree, hf_rbus_payload_double, tvb, offset, length,
               obj->via.f64, "%f", obj->via.f64);
         }
         break;

      case MSGPACK_OBJECT_STR: {
         gchar* str = (gchar*)wmem_alloc(pinfo->pool, obj->via.str.size + 1);
         memcpy(str, obj->via.str.ptr, obj->via.str.size);
         str[obj->via.str.size] = '\0';

         /* Track RBus meta information fields */
         const char* field_label = label;
         if (ctx && !ctx->seen_method && strncmp(str, "METHOD_", 7) == 0) {
            /* This is the method name field */
            ctx->seen_method = TRUE;
            ctx->meta_field_count = 0;
            ctx->method_name = str;
            field_label = "Method";
         } else if (ctx && ctx->seen_method && ctx->meta_field_count < 2) {
            /* These are OpenTelemetry fields after the method */
            if (ctx->meta_field_count == 0) {
               field_label = "OpenTelemetry Parent";
            } else if (ctx->meta_field_count == 1) {
               field_label = "OpenTelemetry State";
            }
            ctx->meta_field_count++;
         } else if (ctx && !ctx->seen_method && ctx->params_count > 0 && ctx->params_seen >= ctx->params_count * 3) {
            /* After all parameter triplets (name, type, value), TRUE/FALSE is the commit flag */
            if (strcmp(str, "TRUE") == 0 || strcmp(str, "FALSE") == 0) {
               field_label = "Commit";
            }
         } else if (ctx && ctx->method_name) {
            /* Method-specific string field handling */
            if (strcmp(ctx->method_name, "METHOD_SETPARAMETERVALUES") == 0) {
               /* SET request: track component name and parameter name fields */
               if (ctx->object_index == 1) {
                  field_label = "Component Name";
               } else if (ctx->params_count > 0 && ctx->params_seen < ctx->params_count * 3) {
                  ctx->params_seen++;
               }
            } else if (strcmp(ctx->method_name, "METHOD_GETPARAMETERVALUES") == 0) {
               /* GET request: first string is component name */
               if (ctx->object_index == 0) {
                  field_label = "Component Name";
               }
            }
         } else if (ctx && !ctx->seen_method && ctx->params_count > 0 && ctx->params_seen < ctx->params_count * 3) {
            /* Track parameter fields before we know the method */
            ctx->params_seen++;
         }

         if (field_label) {
            proto_tree_add_string_format(tree, hf_rbus_payload_string, tvb, offset, length,
               str, "%s: %s", field_label, str[0] ? str : "(empty)");
         } else {
            proto_tree_add_string_format_value(tree, hf_rbus_payload_string, tvb, offset, length,
               str, "%s", str);
         }
         break;
      }

      case MSGPACK_OBJECT_BIN: {
         /* Track parameter fields if we haven't seen the method yet and have a param count */
         if (ctx && !ctx->seen_method && ctx->params_count > 0 && ctx->params_seen < ctx->params_count * 3) {
            ctx->params_seen++;
         }

         /* Check for RBus Boolean encoding (1 byte: 0x00=false, 0x01=true) */
         if (obj->via.bin.size == 1) {
            guint8 byte = ((const guint8*)obj->via.bin.ptr)[0];
            if (byte == 0x00 || byte == 0x01) {
               /* Display as boolean value */
               if (label) {
                  proto_tree_add_boolean_format(tree, hf_rbus_payload_boolean, tvb, offset, length,
                     byte, "%s: %s", label, byte ? "true" : "false");
               } else {
                  proto_tree_add_boolean_format_value(tree, hf_rbus_payload_boolean, tvb, offset, length,
                     byte, "%s", byte ? "true" : "false");
               }
               break;
            }
         }

         /* Check if this binary data is valid UTF-8 text (common for RBus String values) */
         gboolean is_utf8 = TRUE;
         if (obj->via.bin.size > 0) {
            /* Simple UTF-8 validation - check for printable ASCII or valid UTF-8 sequences */
            for (guint32 i = 0; i < obj->via.bin.size; i++) {
               guint8 byte = ((const guint8*)obj->via.bin.ptr)[i];
               /* Allow printable ASCII (0x20-0x7E), tabs, newlines, or null terminator */
               if (byte == 0 && i == obj->via.bin.size - 1) {
                  /* Null terminator at end is OK */
                  continue;
               }
               if (byte < 0x20 && byte != '\t' && byte != '\n' && byte != '\r') {
                  is_utf8 = FALSE;
                  break;
               }
               if (byte > 0x7E && byte < 0xC0) {
                  /* Check for valid UTF-8 continuation bytes */
                  if (byte < 0x80 || byte > 0xBF) {
                     is_utf8 = FALSE;
                     break;
                  }
               }
            }
         }

         if (is_utf8 && obj->via.bin.size > 0) {
            /* Display as string (RBus String type encoded as binary) */
            gchar* str = (gchar*)wmem_alloc(pinfo->pool, obj->via.bin.size + 1);
            memcpy(str, obj->via.bin.ptr, obj->via.bin.size);
            str[obj->via.bin.size] = '\0';
            /* Remove trailing null if present */
            if (obj->via.bin.size > 0 && str[obj->via.bin.size - 1] == '\0') {
               str[obj->via.bin.size - 1] = '\0';
            }
            if (label) {
               proto_tree_add_string_format(tree, hf_rbus_payload_string, tvb, offset, length,
                  str, "%s: %s", label, str);
            } else {
               proto_tree_add_string_format_value(tree, hf_rbus_payload_string, tvb, offset, length,
                  str, "%s", str);
            }
         } else {
            /* Display as binary */
            if (label) {
               proto_tree_add_bytes_format(tree, hf_rbus_payload, tvb, offset, length,
                  NULL, "%s: [Binary, %u bytes]", label, (guint)obj->via.bin.size);
            } else {
               proto_tree_add_bytes_format_value(tree, hf_rbus_payload, tvb, offset, length,
                  NULL, "[Binary, %u bytes]", (guint)obj->via.bin.size);
            }
         }
         break;
      }

      case MSGPACK_OBJECT_ARRAY: {
         proto_tree* array_tree;
         if (label) {
            item = proto_tree_add_bytes_format(tree, hf_rbus_payload, tvb, offset, length,
               NULL, "%s: Array [%u items]", label, obj->via.array.size);
         } else {
            item = proto_tree_add_bytes_format_value(tree, hf_rbus_payload, tvb, offset, length,
               NULL, "Array [%u items]", obj->via.array.size);
         }
         array_tree = proto_item_add_subtree(item, ett_rbus_payload);

         /* Display each array element using the already-parsed structure */
         if (array_tree && obj->via.array.ptr) {
            for (guint32 i = 0; i < obj->via.array.size; i++) {
               gchar* elem_label = wmem_strdup_printf(pinfo->pool, "[%u]", i);
               /* Use 1 byte length for nested elements since we don't track individual sizes */
               display_msgpack_object(array_tree, tvb, pinfo, offset, 1,
                  &obj->via.array.ptr[i], depth + 1, elem_label, ctx);
            }
         }
         break;
      }

      case MSGPACK_OBJECT_MAP: {
         proto_tree* map_tree;
         if (label) {
            item = proto_tree_add_bytes_format(tree, hf_rbus_payload, tvb, offset, length,
               NULL, "%s: Map [%u pairs]", label, obj->via.map.size);
         } else {
            item = proto_tree_add_bytes_format_value(tree, hf_rbus_payload, tvb, offset, length,
               NULL, "Map [%u pairs]", obj->via.map.size);
         }
         map_tree = proto_item_add_subtree(item, ett_rbus_payload);

         /* Display each key-value pair */
         if (map_tree && obj->via.map.ptr) {
            for (guint32 i = 0; i < obj->via.map.size; i++) {
               msgpack_object_kv* kv = &obj->via.map.ptr[i];

               /* Generate label from key */
               gchar* key_label = NULL;
               if (kv->key.type == MSGPACK_OBJECT_STR) {
                  key_label = wmem_strdup_printf(pinfo->pool, "%.*s",
                     (int)kv->key.via.str.size,
                     kv->key.via.str.ptr);
               } else if (kv->key.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                  key_label = wmem_strdup_printf(pinfo->pool, "%" PRIu64, kv->key.via.u64);
               } else {
                  key_label = wmem_strdup_printf(pinfo->pool, "Key %u", i);
               }

               /* Display key and value */
               display_msgpack_object(map_tree, tvb, pinfo, offset, 1,
                  &kv->key, depth + 1, "Key", ctx);
               display_msgpack_object(map_tree, tvb, pinfo, offset, 1,
                  &kv->val, depth + 1, key_label, ctx);
            }
         }
         break;
      }

      default:
         proto_tree_add_item(tree, hf_rbus_payload, tvb, offset, length, ENC_NA);
         break;
   }
}

static guint
dissect_msgpack_value(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,
   guint offset, guint max_len, guint depth, const char* label,
   rbus_parse_context_t* ctx) {
   if (depth > pref_msgpack_depth_limit) {
      proto_tree_add_expert_format(tree, pinfo, &ei_rbus_msgpack_depth_exceeded, tvb, offset, max_len,
         "MessagePack depth limit (%u) exceeded; further nesting not displayed", pref_msgpack_depth_limit);
      return 0; /* Prevent infinite recursion */
   }

   if (max_len < 1) {
      return 0;
   }

   const guint8* data = tvb_get_ptr(tvb, offset, max_len);

   msgpack_unpacked msg;
   msgpack_unpacked_init(&msg);

   size_t off = 0;
   msgpack_unpack_return ret = msgpack_unpack_next(&msg, (const char*)data, max_len, &off);

   if (ret != MSGPACK_UNPACK_SUCCESS) {
      msgpack_unpacked_destroy(&msg);
      return 0;
   }

   /* Use the helper to display the parsed object */
   display_msgpack_object(tree, tvb, pinfo, offset, (guint)off, &msg.data, depth, label, ctx);

   msgpack_unpacked_destroy(&msg);
   return (guint)off;
}

/*
 * Parse structured RBus message payload with dedicated fields
 * Returns the number of bytes consumed
 */
static guint
parse_rbus_payload(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,
   guint offset, guint payload_length) {
   const guint8* data = tvb_get_ptr(tvb, offset, payload_length);
   msgpack_unpacked msg;
   msgpack_unpacked_init(&msg);

   /* Parse all objects in the payload into an array */
#define MAX_OBJECTS 20000
   msgpack_object objects[MAX_OBJECTS];
   guint32 object_count = 0;
   size_t parse_offset = 0;

   while (parse_offset < payload_length && object_count < MAX_OBJECTS) {
      msgpack_unpack_return ret = msgpack_unpack_next(&msg, (const char*)data, payload_length, &parse_offset);
      if (ret != MSGPACK_UNPACK_SUCCESS) {
         break;
      }
      /* Copy the object (msgpack_unpacked will be reused) */
      objects[object_count] = msg.data;
      object_count++;
   }

   if (object_count < 4) {
      msgpack_unpacked_destroy(&msg);
      return 0; /* Need at least method + metadata */
   }

   msgpack_object* array_ptr = objects;
   guint32 array_size = object_count;

   /* Look for method name to determine message type */
   const gchar* method = NULL;
   gint method_idx = -1;
   for (guint32 i = 0; i < array_size; i++) {
      if (array_ptr[i].type == MSGPACK_OBJECT_STR) {
         gchar* str = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[i].via.str.size,
            array_ptr[i].via.str.ptr);
         if (strncmp(str, "METHOD_", 7) == 0) {
            method = str;
            method_idx = i;
            break;
         }
      }
   }

   /* If no METHOD_ found, check if this is an event publication */
   if (!method || method_idx < 0) {
      /* Event Publication Format: [eventName, eventType, hasEventData, [eventData...], hasFilter, [filter...], interval, duration, componentId, ...] */
      if (object_count >= 6) {
         guint idx = 0;

         /* Event Name */
         if (array_ptr[idx].type == MSGPACK_OBJECT_STR) {
            gchar* event_name = wmem_strdup_printf(pinfo->pool, "%.*s",
               (int)array_ptr[idx].via.str.size,
               array_ptr[idx].via.str.ptr);
            proto_tree_add_string(tree, hf_rbus_event_name, tvb, offset, 1, event_name);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Event: %s", event_name);
            idx++;
         } else {
            msgpack_unpacked_destroy(&msg);
            return 0;
         }

         /* Event Type */
         if (idx < object_count && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            guint32 event_type = (guint32)array_ptr[idx].via.u64;
            proto_tree_add_uint(tree, hf_rbus_event_type, tvb, offset, 1, event_type);
            idx++;
         }

         /* Has Event Data */
         gboolean has_event_data = FALSE;
         if (idx < object_count && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            has_event_data = (array_ptr[idx].via.u64 != 0);
            proto_tree_add_boolean(tree, hf_rbus_has_event_data, tvb, offset, 1, has_event_data);
            idx++;
         }

         /* Parse Event Data (rbusObject with properties) */
         /* rbusObject in event publications is just a placeholder string, followed by property data */
         if (has_event_data && idx < object_count) {
            /* Skip the placeholder rbusObject (usually a 1-byte string) */
            idx++;
         }

         /* Has Filter */
         if (idx < object_count && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            gboolean has_filter = (array_ptr[idx].via.u64 != 0);
            proto_tree_add_boolean(tree, hf_rbus_has_filter, tvb, offset, 1, has_filter);
            idx++;

            /* Skip filter data if present (not parsing filter details yet) */
            if (has_filter && idx < object_count) {
               idx++; /* Skip filter object */
            }
         }

         /* Now parse the property data: [prop_count, name, type, value, ...] */
         if (has_event_data && idx < object_count) {
            guint32 prop_count = 0;
            if (array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
               prop_count = (guint32)array_ptr[idx].via.u64;
               idx++;
            }

            proto_item* data_item = proto_tree_add_item(tree, hf_rbus_event_data, tvb, offset, 1, ENC_NA);
            proto_tree* data_tree = proto_item_add_subtree(data_item, ett_rbus_property);
            proto_item_append_text(data_item, " (%u properties)", prop_count);

            /* Parse properties as triplets: name, type, value */
            for (guint32 p = 0; p < prop_count && idx + 2 < object_count; p++) {
               gchar* name = NULL;
               guint32 type_id = 0;

               /* Property Name */
               if (array_ptr[idx].type == MSGPACK_OBJECT_STR) {
                  name = wmem_strdup_printf(pinfo->pool, "%.*s",
                     (int)array_ptr[idx].via.str.size,
                     array_ptr[idx].via.str.ptr);
               }
               idx++;

               /* Property Type */
               if (idx < object_count && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                  type_id = (guint32)array_ptr[idx].via.u64;
               }
               idx++;

               /* Property Value */
               if (idx < object_count && name) {
                  proto_item* prop_item = proto_tree_add_item(data_tree, hf_rbus_object_property, tvb, offset, 1, ENC_NA);
                  proto_tree* prop_tree = proto_item_add_subtree(prop_item, ett_rbus_property);
                  proto_item_append_text(prop_item, ": %s", name);

                  proto_tree_add_string(prop_tree, hf_rbus_object_property_name, tvb, offset, 1, name);
                  proto_tree_add_uint(prop_tree, hf_rbus_property_type, tvb, offset, 1, type_id);

                  gchar* value_str = add_typed_value(prop_tree, tvb, pinfo, offset, &array_ptr[idx], TRUE);

                  if (value_str) {
                     gchar* namevalue = wmem_strdup_printf(pinfo->pool, "%s=%s", name, value_str);
                     proto_tree_add_string(prop_tree, hf_rbus_object_property_namevalue, tvb, offset, 1, namevalue);
                  }
               }
               idx++;
            }
         }

         /* Interval */
         if (idx < object_count && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            proto_tree_add_uint(tree, hf_rbus_interval, tvb, offset, 1, (guint32)array_ptr[idx].via.u64);
            idx++;
         }

         /* Duration */
         if (idx < object_count && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            proto_tree_add_uint(tree, hf_rbus_duration, tvb, offset, 1, (guint32)array_ptr[idx].via.u64);
            idx++;
         }

         /* Component ID */
         if (idx < object_count && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            proto_tree_add_int(tree, hf_rbus_component_id, tvb, offset, 1, (gint32)array_ptr[idx].via.u64);
            idx++;
         }

         msgpack_unpacked_destroy(&msg);
         return payload_length;
      }

      msgpack_unpacked_destroy(&msg);
      return 0; /* No method found and not an event */
   }

   /* Create metadata subtree */
   proto_item* meta_item = proto_tree_add_item(tree, hf_rbus_metadata, tvb, offset, 1, ENC_NA);
   proto_tree* meta_tree = proto_item_add_subtree(meta_item, ett_rbus_metadata);

   /* Add method name */
   proto_tree_add_string(meta_tree, hf_rbus_method_name, tvb, offset, 1, method);

   /* Add OT fields if present */
   if (method_idx + 1 < (gint)array_size && array_ptr[method_idx + 1].type == MSGPACK_OBJECT_STR) {
      gchar* ot_parent = wmem_strdup_printf(pinfo->pool, "%.*s",
         (int)array_ptr[method_idx + 1].via.str.size,
         array_ptr[method_idx + 1].via.str.ptr);
      proto_tree_add_string(meta_tree, hf_rbus_ot_parent, tvb, offset, 1, ot_parent);
   }
   if (method_idx + 2 < (gint)array_size && array_ptr[method_idx + 2].type == MSGPACK_OBJECT_STR) {
      gchar* ot_state = wmem_strdup_printf(pinfo->pool, "%.*s",
         (int)array_ptr[method_idx + 2].via.str.size,
         array_ptr[method_idx + 2].via.str.ptr);
      proto_tree_add_string(meta_tree, hf_rbus_ot_state, tvb, offset, 1, ot_state);
   }
   /* Add offset field if present */
   if (method_idx + 3 < (gint)array_size) {
      gint32 offset_val = 0;
      if (array_ptr[method_idx + 3].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         offset_val = (gint32)array_ptr[method_idx + 3].via.u64;
      } else if (array_ptr[method_idx + 3].type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
         offset_val = (gint32)array_ptr[method_idx + 3].via.i64;
      }
      proto_tree_add_int(meta_tree, hf_rbus_metadata_offset, tvb, offset, 1, offset_val);
   }

   /* Parse based on method type */
   if (strcmp(method, "METHOD_GETPARAMETERVALUES") == 0) {
      /* GET Request: [componentName, paramCount, parameterName, ...] */
      if (array_size >= 3) {
         if (array_ptr[0].type == MSGPACK_OBJECT_STR) {
            gchar* comp = wmem_strdup_printf(pinfo->pool, "%.*s",
               (int)array_ptr[0].via.str.size,
               array_ptr[0].via.str.ptr);
            proto_tree_add_string(tree, hf_rbus_component_name, tvb, offset, 1, comp);
         }
         if (array_ptr[1].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            proto_tree_add_uint(tree, hf_rbus_param_count, tvb, offset, 1,
               (guint32)array_ptr[1].via.u64);
         }
         /* Add parameter names */
         for (guint32 i = 2; i < (guint32)method_idx; i++) {
            if (array_ptr[i].type == MSGPACK_OBJECT_STR) {
               gchar* param = wmem_strdup_printf(pinfo->pool, "%.*s",
                  (int)array_ptr[i].via.str.size,
                  array_ptr[i].via.str.ptr);
               proto_tree_add_string(tree, hf_rbus_parameter_name, tvb, offset, 1, param);
            }
         }
      }
   } else if (strcmp(method, "METHOD_SUBSCRIBE") == 0) {
      /* SUBSCRIBE Request: [event_name, reply_topic, has_payload, payload, publishOnSubscribe, rawData, ...] */
      guint idx = 0;

      /* Event name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* event = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_event_name, tvb, offset, 1, event);
         idx++;
      }

      /* Reply topic */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* reply = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_reply_topic_payload, tvb, offset, 1, reply);
         idx++;
      }

      /* Remaining fields: has_payload, payload (optional), publishOnSubscribe, rawData */
      /* We can skip detailed parsing of these for now */
   } else if (strcmp(method, "METHOD_UNSUBSCRIBE") == 0) {
      /* UNSUBSCRIBE Request: Same structure as SUBSCRIBE */
      guint idx = 0;

      /* Event name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* event = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_event_name, tvb, offset, 1, event);
         idx++;
      }

      /* Reply topic */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* reply = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_reply_topic_payload, tvb, offset, 1, reply);
         idx++;
      }
   } else if (strcmp(method, "METHOD_RPC") == 0) {
      /* RPC/Invoke Request: [sessionId, methodName, hasParams, params (optional)] */
      guint idx = 0;

      /* Session ID */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         proto_tree_add_uint(tree, hf_rbus_session_id, tvb, offset, 1,
            (guint32)array_ptr[idx].via.u64);
         idx++;
      }

      /* Method name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* method_name = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_invoke_method_name, tvb, offset, 1, method_name);
         idx++;
      }

      /* Has params flag */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         gint32 has_params = (gint32)array_ptr[idx].via.u64;
         proto_tree_add_int(tree, hf_rbus_has_params, tvb, offset, 1, has_params);
         idx++;
      }

      /* Params would be an RBusObject - we can add detailed parsing later if needed */
   } else if (strcmp(method, "METHOD_COMMIT") == 0) {
      /* COMMIT Request: [sessionId, componentName, paramCount] */
      guint idx = 0;

      /* Session ID */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         proto_tree_add_uint(tree, hf_rbus_session_id, tvb, offset, 1,
            (guint32)array_ptr[idx].via.u64);
         idx++;
      }

      /* Component name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* comp = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_component_name, tvb, offset, 1, comp);
         idx++;
      }

      /* Param count */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         proto_tree_add_uint(tree, hf_rbus_param_count, tvb, offset, 1,
            (guint32)array_ptr[idx].via.u64);
         idx++;
      }
   } else if (strcmp(method, "METHOD_GETPARAMETERNAMES") == 0) {
      /* GETPARAMETERNAMES Request: [componentName, paramName, nextLevel] */
      guint idx = 0;

      /* Component name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* comp = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_component_name, tvb, offset, 1, comp);
         idx++;
      }

      /* Parameter name (path for discovery) */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* param = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_parameter_name, tvb, offset, 1, param);
         idx++;
      }

      /* Next level flag */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         proto_tree_add_uint(tree, hf_rbus_param_count, tvb, offset, 1,
            (guint32)array_ptr[idx].via.u64);
         idx++;
      }
   } else if (strcmp(method, "METHOD_SETPARAMETERATTRIBUTES") == 0 ||
      strcmp(method, "METHOD_GETPARAMETERATTRIBUTES") == 0) {
      /* Attributes requests - basic parsing */
      guint idx = 0;

      /* Component name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* comp = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_component_name, tvb, offset, 1, comp);
         idx++;
      }

      /* Show remaining fields generically */
      while (idx < (guint)method_idx) {
         if (array_ptr[idx].type == MSGPACK_OBJECT_STR) {
            gchar* str = wmem_strdup_printf(pinfo->pool, "%.*s",
               (int)array_ptr[idx].via.str.size,
               array_ptr[idx].via.str.ptr);
            proto_tree_add_string(tree, hf_rbus_parameter_name, tvb, offset, 1, str);
         } else if (array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            proto_tree_add_uint(tree, hf_rbus_param_count, tvb, offset, 1,
               (guint32)array_ptr[idx].via.u64);
         }
         idx++;
      }
   } else if (strcmp(method, "METHOD_ADDTBLROW") == 0 || strcmp(method, "METHOD_DELETETBLROW") == 0) {
      /* Table row operations: [sessionId, componentName, tableName, alias/rowIndex] */
      guint idx = 0;

      /* Session ID */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         proto_tree_add_uint(tree, hf_rbus_session_id, tvb, offset, 1,
            (guint32)array_ptr[idx].via.u64);
         idx++;
      }

      /* Component name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* comp = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_component_name, tvb, offset, 1, comp);
         idx++;
      }

      /* Table name */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* table = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_parameter_name, tvb, offset, 1, table);
         idx++;
      }

      /* Alias or row index */
      if (idx < (guint)method_idx) {
         if (array_ptr[idx].type == MSGPACK_OBJECT_STR) {
            gchar* alias = wmem_strdup_printf(pinfo->pool, "%.*s",
               (int)array_ptr[idx].via.str.size,
               array_ptr[idx].via.str.ptr);
            proto_tree_add_string(tree, hf_rbus_parameter_name, tvb, offset, 1, alias);
         } else if (array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            proto_tree_add_uint(tree, hf_rbus_param_count, tvb, offset, 1,
               (guint32)array_ptr[idx].via.u64);
         }
         idx++;
      }
   } else if (strcmp(method, "METHOD_OPENDIRECT_CONN") == 0 ||
      strcmp(method, "METHOD_CLOSEDIRECT_CONN") == 0) {
      /* Direct connection methods - show any string fields */
      guint idx = 0;

      while (idx < (guint)method_idx) {
         if (array_ptr[idx].type == MSGPACK_OBJECT_STR) {
            gchar* str = wmem_strdup_printf(pinfo->pool, "%.*s",
               (int)array_ptr[idx].via.str.size,
               array_ptr[idx].via.str.ptr);
            proto_tree_add_string(tree, hf_rbus_component_name, tvb, offset, 1, str);
         }
         idx++;
      }
   } else if (strcmp(method, "METHOD_SETPARAMETERVALUES") == 0) {
      /* SET Request: [sessionId, componentName, rollback, paramCount, params..., commit] */
      guint idx = 0;
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         proto_tree_add_uint(tree, hf_rbus_session_id, tvb, offset, 1,
            (guint32)array_ptr[idx].via.u64);
         idx++;
      }
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* comp = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_component_name, tvb, offset, 1, comp);
         idx++;
      }
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         proto_tree_add_uint(tree, hf_rbus_rollback, tvb, offset, 1,
            (guint32)array_ptr[idx].via.u64);
         idx++;
      }
      guint32 param_count = 0;
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
         param_count = (guint32)array_ptr[idx].via.u64;
         proto_tree_add_uint(tree, hf_rbus_param_count, tvb, offset, 1, param_count);
         idx++;
      }

      /* Parse parameters (triplets: name, type, value) */
      for (guint32 p = 0; p < param_count && idx + 2 <= (guint)method_idx; p++) {
         proto_item* param_item = proto_tree_add_item(tree, hf_rbus_parameter, tvb, offset, 1, ENC_NA);
         proto_tree* param_tree = proto_item_add_subtree(param_item, ett_rbus_parameter);

         /* Name */
         gchar* name = NULL;
         if (array_ptr[idx].type == MSGPACK_OBJECT_STR) {
            name = wmem_strdup_printf(pinfo->pool, "%.*s",
               (int)array_ptr[idx].via.str.size,
               array_ptr[idx].via.str.ptr);
            proto_tree_add_string(param_tree, hf_rbus_parameter_name, tvb, offset, 1, name);
            proto_item_append_text(param_item, ": %s", name);
         }
         idx++;

         /* Type */
         guint32 type_id = 0;
         if (array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            type_id = (guint32)array_ptr[idx].via.u64;
            proto_tree_add_uint(param_tree, hf_rbus_parameter_type, tvb, offset, 1, type_id);
         }
         idx++;

         /* Value */
         gchar* value_str = NULL;
         if (idx < (guint)method_idx) {
            value_str = add_typed_value(param_tree, tvb, pinfo, offset, &array_ptr[idx], FALSE);

            /* Add synthetic namevalue field for filtering */
            if (name && value_str) {
               gchar* namevalue = wmem_strdup_printf(pinfo->pool, "%s=%s", name, value_str);
               proto_tree_add_string(param_tree, hf_rbus_parameter_namevalue, tvb, offset, 1, namevalue);
            }
         }
         idx++;
      }

      /* Commit flag */
      if (idx < (guint)method_idx && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
         gchar* commit = wmem_strdup_printf(pinfo->pool, "%.*s",
            (int)array_ptr[idx].via.str.size,
            array_ptr[idx].via.str.ptr);
         proto_tree_add_string(tree, hf_rbus_commit, tvb, offset, 1, commit);
      }
   } else if (strcmp(method, "METHOD_RESPONSE") == 0) {
      /* Response: [errorCode, propertyCount, properties..., method, ot_parent, ot_state, offset] */
      guint idx = 0;

      /* Error Code (first field in response) */
      gint32 error_code = 0;
      if (idx < (guint)method_idx) {
         if (array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            error_code = (gint32)array_ptr[idx].via.u64;
         } else if (array_ptr[idx].type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            error_code = (gint32)array_ptr[idx].via.i64;
         }
         proto_tree_add_int(tree, hf_rbus_error_code, tvb, offset, 1, error_code);
         idx++;
      }

      /* Try to find and parse properties regardless of error code.
       * Some responses may include property data even with non-zero error codes. */
      if (idx < (guint)method_idx) {
         /* First, check if next field is a failed element name string (for simple error responses) */
         gboolean is_simple_error = FALSE;
         if (error_code != 0 && array_ptr[idx].type == MSGPACK_OBJECT_STR) {
            /* Check if this looks like a failed element name by seeing if the string after is METHOD_ */
            if (idx + 1 < (guint)method_idx && array_ptr[idx + 1].type == MSGPACK_OBJECT_STR) {
               gchar* next_str = wmem_strdup_printf(pinfo->pool, "%.*s",
                  (int)array_ptr[idx + 1].via.str.size,
                  array_ptr[idx + 1].via.str.ptr);
               if (strncmp(next_str, "METHOD_", 7) == 0) {
                  /* This is a simple error response with just a failed element name */
                  is_simple_error = TRUE;
                  gchar* failed = wmem_strdup_printf(pinfo->pool, "%.*s",
                     (int)array_ptr[idx].via.str.size,
                     array_ptr[idx].via.str.ptr);
                  proto_tree_add_string(tree, hf_rbus_failed_element, tvb, offset, 1, failed);
                  idx++;
               }
            }
         }

         /* If not a simple error response, look for property count */
         if (!is_simple_error) {
            /* Look for property count: an integer that's followed by the expected structure
             * This handles new protocol fields between error code and property count */
            guint32 prop_count = 0;
            gboolean found_prop_count = FALSE;
            
            while (idx < (guint)method_idx && !found_prop_count) {
               if ((array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
                    array_ptr[idx].type == MSGPACK_OBJECT_NEGATIVE_INTEGER)) {
                  guint32 potential_count = (array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) ? 
                                            (guint32)array_ptr[idx].via.u64 : 
                                            (guint32)array_ptr[idx].via.i64;
                  
                  /* Verify this looks like a property count by checking if next field matches expectations:
                   * - If count > 0: next field should be a string (property name)
                   * - If count == 0: should be near the METHOD_ field */
                  if (potential_count > 0 && idx + 1 < (guint)method_idx && 
                      array_ptr[idx + 1].type == MSGPACK_OBJECT_STR) {
                     /* Non-zero count followed by string - this is the property count */
                     prop_count = potential_count;
                     found_prop_count = TRUE;
                     proto_tree_add_uint(tree, hf_rbus_property_count, tvb, offset, 1, prop_count);
                     idx++;
                     break;
                  } else if (potential_count == 0 && idx + 1 < (guint)method_idx && 
                             array_ptr[idx + 1].type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
                             array_ptr[idx + 1].type != MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                     /* Zero count not followed by another integer - likely the property count */
                     prop_count = 0;
                     found_prop_count = TRUE;
                     proto_tree_add_uint(tree, hf_rbus_property_count, tvb, offset, 1, prop_count);
                     idx++;
                     break;
                  }
               }
               idx++;
            }

            /* Parse properties (triplets: name, type, value) */
            for (guint32 p = 0; p < prop_count && idx + 2 <= (guint)method_idx; p++) {
               proto_item* prop_item = proto_tree_add_item(tree, hf_rbus_property, tvb, offset, 1, ENC_NA);
               proto_tree* prop_tree = proto_item_add_subtree(prop_item, ett_rbus_property);

               /* Name */
               gchar* name = NULL;
               if (array_ptr[idx].type == MSGPACK_OBJECT_STR) {
                  name = wmem_strdup_printf(pinfo->pool, "%.*s",
                     (int)array_ptr[idx].via.str.size,
                     array_ptr[idx].via.str.ptr);
                  proto_tree_add_string(prop_tree, hf_rbus_property_name, tvb, offset, 1, name);
                  proto_item_append_text(prop_item, ": %s", name);
               }
               idx++;

               /* Type */
               guint32 type_id = 0;
               if (array_ptr[idx].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                  type_id = (guint32)array_ptr[idx].via.u64;
                  proto_tree_add_uint(prop_tree, hf_rbus_property_type, tvb, offset, 1, type_id);
               }
               idx++;

               /* Value */
               gchar* value_str = NULL;
               if (idx < (guint)method_idx) {
                  value_str = add_typed_value(prop_tree, tvb, pinfo, offset, &array_ptr[idx], TRUE);

                  /* Add synthetic namevalue field for filtering */
                  if (name && value_str) {
                     gchar* namevalue = wmem_strdup_printf(pinfo->pool, "%s=%s", name, value_str);
                     proto_tree_add_string(prop_tree, hf_rbus_property_namevalue, tvb, offset, 1, namevalue);
                  }
               }
               idx++;
            }
         }
      }
   }

   msgpack_unpacked_destroy(&msg);
   return payload_length;
}

/*
 * Dissect the RBus protocol
 */
static int
dissect_rbus(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
   proto_item* ti;
   proto_tree* rbus_tree;
   proto_tree* header_tree;
   guint offset = 0;
   guint32 header_length;
   guint32 payload_length;
   guint32 topic_length;
   guint32 reply_topic_length;
   guint64 flags;
   guint32 control_data;
   const guint8* topic_str = NULL;
   const guint8* reply_topic_str = NULL;

   /* Check if we have enough data for minimal header (marker + version + header_length) */
   guint available = tvb_captured_length(tvb);
   if (available < 6) {
      /* Need more data for TCP desegmentation */
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return -((gint)available);
   }

   /* Read header_length to calculate total message size */
   guint16 header_len = tvb_get_ntohs(tvb, 4);

   /* Total message = header_length + payload_length
    * We need to read up to the payload_length field (offset 18) to calculate total */
   if (available < 22) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return -((gint)available);
   }

   /* Read payload_length - offset 18 after marker(2) + version(2) + header_len(2) + seq(4) + flags(4) + control(4) */
   guint32 payload_len = tvb_get_ntohl(tvb, 18);

   /* Calculate total message length: header_length + payload_length */
   guint32 total_len = header_len + payload_len;

   /* Check if we have the complete message */
   if (available < total_len) {
      /* Need more data - request exactly what we need */
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = total_len - available;
      return -((gint)available);
   }

   /* Set protocol column */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, RBUS_PROTOCOL_SHORT_NAME);
   col_clear(pinfo->cinfo, COL_INFO);

   /* Create protocol tree */
   ti = proto_tree_add_item(tree, proto_rbus, tvb, 0, -1, ENC_NA);
   rbus_tree = proto_item_add_subtree(ti, ett_rbus);

   /* Create header subtree */
   header_tree = proto_tree_add_subtree(rbus_tree, tvb, offset, 0,
      ett_rbus_header, &ti, "RBus Message Header");

   /* Parse header fields - wire format has opening marker at offset 0 */
   proto_tree_add_item(header_tree, hf_rbus_opening_marker, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(header_tree, hf_rbus_version, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item_ret_uint(header_tree, hf_rbus_header_length, tvb, offset, 2,
      ENC_BIG_ENDIAN, &header_length);
   offset += 2;

   proto_tree_add_item(header_tree, hf_rbus_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   /* Flags field with bit breakdown */
   static int* const flags_bits[] = {
       &hf_rbus_flags_request,
       &hf_rbus_flags_response,
       &hf_rbus_flags_undeliverable,
       &hf_rbus_flags_tainted,
       &hf_rbus_flags_raw_binary,
       &hf_rbus_flags_encrypted,
       NULL
   };
   proto_tree_add_bitmask_ret_uint64(header_tree, tvb, offset, hf_rbus_flags,
      ett_rbus_flags, flags_bits, ENC_BIG_ENDIAN, &flags);
   offset += 4;

   proto_tree_add_item_ret_uint(header_tree, hf_rbus_control_data, tvb, offset, 4, ENC_BIG_ENDIAN, &control_data);
   offset += 4;

   proto_tree_add_item_ret_uint(header_tree, hf_rbus_payload_length, tvb, offset, 4,
      ENC_BIG_ENDIAN, &payload_length);
   offset += 4;

   /* Validate lengths */
   if (header_length > tvb_captured_length(tvb) ||
      payload_length > RBUS_MAX_PAYLOAD_SIZE) {
      expert_add_info(pinfo, ti, &ei_rbus_invalid_length);
      return tvb_captured_length(tvb);
   }

   /* Topic length and string */
   proto_tree_add_item_ret_uint(header_tree, hf_rbus_topic_length, tvb, offset, 4,
      ENC_BIG_ENDIAN, &topic_length);
   offset += 4;

   if (topic_length > 0 && topic_length < RBUS_MAX_TOPIC_LENGTH) {
      proto_tree_add_item_ret_string(header_tree, hf_rbus_topic, tvb, offset,
         topic_length, ENC_UTF_8 | ENC_NA,
         pinfo->pool, &topic_str);
      offset += topic_length;

      /* Build info column with message type and topic */
      const char* msg_type = "Message";

      if (flags & 0x01) {
         /* Request flag set */
         if (control_data == 0) {
            msg_type = "Request";
         } else {
            msg_type = "Request (forwarded)";
         }
      } else if (flags & 0x02) {
         /* Response flag set */
         if (control_data == 0) {
            msg_type = "Response";
         } else {
            msg_type = "Response (forwarded)";
         }
      }

      if (topic_str) {
         col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", msg_type, topic_str);
      } else {
         col_add_str(pinfo->cinfo, COL_INFO, msg_type);
      }
   }

   /* Reply topic length and string */
   proto_tree_add_item_ret_uint(header_tree, hf_rbus_reply_topic_length, tvb, offset, 4,
      ENC_BIG_ENDIAN, &reply_topic_length);
   offset += 4;

   if (reply_topic_length > 0 && reply_topic_length < RBUS_MAX_TOPIC_LENGTH) {
      proto_tree_add_item_ret_string(header_tree, hf_rbus_reply_topic, tvb, offset,
         reply_topic_length, ENC_UTF_8 | ENC_NA,
         pinfo->pool, &reply_topic_str);
      offset += reply_topic_length;
   }

   /* Optional MSG_ROUNDTRIP_TIME fields - check if there's room for timestamps + closing marker */
   guint remaining_header = tvb_captured_length_remaining(tvb, offset);

   /* If there are 22+ bytes remaining (20 for timestamps + 2 for closing marker), check for roundtrip */
   if (remaining_header >= 22) {
      /* Peek ahead to see if closing marker is at offset+20 (after 5 timestamps) */
      guint16 potential_marker = tvb_get_ntohs(tvb, offset + 20);
      if (potential_marker == 0xAAAA) {
         /* Parse the 5 roundtrip timestamp fields (T1-T5) */
         proto_tree_add_item(header_tree, hf_rbus_roundtrip_t1, tvb, offset, 4, ENC_BIG_ENDIAN);
         offset += 4;
         proto_tree_add_item(header_tree, hf_rbus_roundtrip_t2, tvb, offset, 4, ENC_BIG_ENDIAN);
         offset += 4;
         proto_tree_add_item(header_tree, hf_rbus_roundtrip_t3, tvb, offset, 4, ENC_BIG_ENDIAN);
         offset += 4;
         proto_tree_add_item(header_tree, hf_rbus_roundtrip_t4, tvb, offset, 4, ENC_BIG_ENDIAN);
         offset += 4;
         proto_tree_add_item(header_tree, hf_rbus_roundtrip_t5, tvb, offset, 4, ENC_BIG_ENDIAN);
         offset += 4;
      }
   }

   /* Closing marker (0xAAAA) - always present after reply_topic (or after roundtrip fields if present) */
   if (remaining_header >= 2) {
      guint16 closing_marker = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(header_tree, hf_rbus_closing_marker, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      if (closing_marker != 0xAAAA) {
         expert_add_info(pinfo, ti, &ei_rbus_malformed_header);
      }
   }

   /* Update header tree length */
   proto_item_set_len(ti, offset);

   /* Payload - decode MessagePack */
   if (payload_length > 0) {
      /* Verify we have enough data in the TVB for the payload */
      guint remaining = tvb_captured_length_remaining(tvb, offset);
      guint actual_payload_length = payload_length;

      if (remaining < payload_length) {
         /* This shouldn't happen after desegmentation, but handle it gracefully */
         expert_add_info(pinfo, ti, &ei_rbus_truncated_packet);
         actual_payload_length = remaining;
      }

      if (actual_payload_length > 0) {
         proto_tree* payload_tree;
         proto_item* payload_item;

         /* Only try to add the item with the length we actually have */
         payload_item = proto_tree_add_item(rbus_tree, hf_rbus_payload, tvb, offset,
            actual_payload_length, ENC_NA);
         payload_tree = proto_item_add_subtree(payload_item, ett_rbus_payload);

         /* Check if payload is JSON (starts with '{' or '[') */
         guint8 first_byte = tvb_get_uint8(tvb, offset);
         if ((first_byte == '{' || first_byte == '[') && actual_payload_length > 1) {
            /* This is likely JSON, not MessagePack - display as string */
            const guint8* json_data = tvb_get_ptr(tvb, offset, actual_payload_length);
            gchar* json_str = (gchar*)wmem_alloc(pinfo->pool, actual_payload_length + 1);
            memcpy(json_str, json_data, actual_payload_length);
            json_str[actual_payload_length] = '\0';

            proto_tree_add_bytes_format_value(payload_tree, hf_rbus_payload, tvb, offset,
               actual_payload_length, NULL, "%s", json_str);
            proto_item_append_text(payload_item, " [JSON]");
         } else {
            /* Try structured RBus message parsing first */
            guint consumed = parse_rbus_payload(tvb, pinfo, payload_tree, offset, actual_payload_length);

            if (consumed == 0) {
               /* Fall back to generic MessagePack parsing */
               guint payload_offset = offset;
               guint end_offset = offset + actual_payload_length;
               guint object_count = 0;
               guint total_consumed = 0;

               /* Initialize parsing context to track meta information fields */
               rbus_parse_context_t parse_ctx = {0, FALSE, 0, NULL, 0, 0};

               while (payload_offset < end_offset) {
                  /* Make sure we don't go beyond what's available */
                  guint available = tvb_captured_length_remaining(tvb, payload_offset);
                  if (available == 0) {
                     break;
                  }

                  guint max_len = (end_offset - payload_offset < available) ?
                     end_offset - payload_offset : available;

                  parse_ctx.object_index = object_count;
                  guint consumed_bytes = dissect_msgpack_value(tvb, pinfo, payload_tree,
                     payload_offset,
                     max_len,
                     0, NULL, &parse_ctx);

                  if (consumed_bytes == 0) {
                     /* Failed to decode, show remaining as raw */
                     if (payload_offset < end_offset) {
                        proto_tree_add_item(payload_tree, hf_rbus_payload, tvb,
                           payload_offset, end_offset - payload_offset, ENC_NA);
                     }
                     break;
                  }

                  payload_offset += consumed_bytes;
                  total_consumed += consumed_bytes;
                  object_count++;

                  /* Safety limit to prevent infinite loops */
                  if (object_count >= pref_msgpack_object_limit) {
                     proto_tree_add_expert_format(payload_tree, pinfo, &ei_rbus_msgpack_depth_exceeded, tvb,
                        payload_offset, end_offset - payload_offset,
                        "MessagePack object limit (%u) reached; remaining %u bytes not decoded",
                        pref_msgpack_object_limit, end_offset - payload_offset);
                     break;
                  }
               }

               if (total_consumed > 0) {
                  proto_item_append_text(payload_item, " [%u MessagePack object%s]",
                     object_count, object_count == 1 ? "" : "s");
               } else {
                  proto_item_append_text(payload_item, " [Not valid MessagePack]");
               }
            } else {
               proto_item_append_text(payload_item, " [Structured RBus Message]");
            }
         }

         offset += payload_length;
      }
   }

   return offset;
}

/*
 * Heuristic dissector to auto-detect RBus protocol
 */
static bool
dissect_rbus_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {
   /* Need at least 22 bytes for basic header check (up to payload_length field) */
   if (tvb_captured_length(tvb) < 22) {
      return false;
   }

   /* Check for RBus marker (0xAAAA) */
   guint16 marker = tvb_get_ntohs(tvb, 0);
   if (marker != 0xAAAA) {
      return false;
   }

   /* Check for reasonable version field (currently version 2) */
   guint16 version = tvb_get_ntohs(tvb, 2);
   if (version != 2) {
      return false;
   }

   /* Check header length is reasonable */
   guint16 header_length = tvb_get_ntohs(tvb, 4);
   if (header_length < 32 || header_length > 4096) {
      return false;
   }

   /* Check payload length is reasonable (now at offset 18: 2+2+2+4+4+4=18) */
   guint32 payload_length = tvb_get_ntohl(tvb, 18);
   if (payload_length > RBUS_MAX_PAYLOAD_SIZE) {
      return false;
   }

   /* Looks like RBus, dissect it */
   dissect_rbus(tvb, pinfo, tree, data);
   return true;
}

/*
 * Register protocol fields and subtrees
 */
void
proto_register_rbus(void) {
   static hf_register_info hf[] = {
       { &hf_rbus_header,
         { "Header", "rbus.header",
           FT_NONE, BASE_NONE, NULL, 0x0,
           "RBus message header", HFILL }
       },
       { &hf_rbus_opening_marker,
         { "Opening Marker", "rbus.header.opening_marker",
           FT_UINT16, BASE_HEX, NULL, 0x0,
           "Header opening marker (0xAAAA) - marks header start", HFILL }
       },
       { &hf_rbus_version,
         { "Version", "rbus.header.version",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Protocol version", HFILL }
       },
       { &hf_rbus_header_length,
         { "Header Length", "rbus.header.length",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Total header length in bytes", HFILL }
       },
       { &hf_rbus_sequence_number,
         { "Sequence Number", "rbus.header.sequence",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Message sequence number", HFILL }
       },
       { &hf_rbus_control_data,
         { "Control Data", "rbus.header.control_data",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           "Control flags and metadata", HFILL }
       },
       { &hf_rbus_payload_length,
         { "Payload Length", "rbus.header.payload_length",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Payload size in bytes", HFILL }
       },
       { &hf_rbus_topic_length,
         { "Topic Length", "rbus.header.topic_length",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Topic string length", HFILL }
       },
       { &hf_rbus_topic,
         { "Topic", "rbus.header.topic",
           FT_STRING, BASE_NONE, NULL, 0x0,
           "Message topic (destination)", HFILL }
       },
       { &hf_rbus_reply_topic_length,
         { "Reply Topic Length", "rbus.header.reply_topic_length",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Reply topic string length", HFILL }
       },
       { &hf_rbus_reply_topic,
         { "Reply Topic", "rbus.header.reply_topic",
           FT_STRING, BASE_NONE, NULL, 0x0,
           "Reply destination topic", HFILL }
       },
       { &hf_rbus_roundtrip_t1,
         { "Roundtrip T1", "rbus.header.roundtrip.t1",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Time at which consumer sends the request to daemon", HFILL }
       },
       { &hf_rbus_roundtrip_t2,
         { "Roundtrip T2", "rbus.header.roundtrip.t2",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Time at which daemon receives the message from consumer", HFILL }
       },
       { &hf_rbus_roundtrip_t3,
         { "Roundtrip T3", "rbus.header.roundtrip.t3",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Time at which daemon writes to provider socket", HFILL }
       },
       { &hf_rbus_roundtrip_t4,
         { "Roundtrip T4", "rbus.header.roundtrip.t4",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Time at which provider sends back the response", HFILL }
       },
       { &hf_rbus_roundtrip_t5,
         { "Roundtrip T5", "rbus.header.roundtrip.t5",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Time at which daemon received the response", HFILL }
       },
       { &hf_rbus_closing_marker,
         { "Closing Marker", "rbus.header.closing_marker",
           FT_UINT16, BASE_HEX, NULL, 0x0,
           "Header closing marker (0xAAAA) - marks header end", HFILL }
       },
       { &hf_rbus_flags,
         { "Flags", "rbus.header.flags",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           "Message flags", HFILL }
       },
       { &hf_rbus_flags_request,
         { "Request", "rbus.header.flags.request",
           FT_BOOLEAN, 32, NULL, 0x01,
           "Request message", HFILL }
       },
       { &hf_rbus_flags_response,
         { "Response", "rbus.header.flags.response",
           FT_BOOLEAN, 32, NULL, 0x02,
           "Response message", HFILL }
       },
       { &hf_rbus_flags_undeliverable,
         { "Undeliverable", "rbus.header.flags.undeliverable",
           FT_BOOLEAN, 32, NULL, 0x04,
           "Message could not be delivered", HFILL }
       },
       { &hf_rbus_flags_tainted,
         { "Tainted", "rbus.header.flags.tainted",
           FT_BOOLEAN, 32, NULL, 0x08,
           "Message is tainted (for benchmarking)", HFILL }
       },
       { &hf_rbus_flags_raw_binary,
         { "Raw Binary", "rbus.header.flags.raw_binary",
           FT_BOOLEAN, 32, NULL, 0x10,
           "Raw binary payload", HFILL }
       },
       { &hf_rbus_flags_encrypted,
         { "Encrypted", "rbus.header.flags.encrypted",
           FT_BOOLEAN, 32, NULL, 0x20,
           "Encrypted payload", HFILL }
       },
       { &hf_rbus_payload,
         { "Payload", "rbus.payload",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           "MessagePack encoded payload", HFILL }
       },
       { &hf_rbus_payload_string,
         { "Payload", "rbus.payload.string",
           FT_STRING, BASE_NONE, NULL, 0x0,
           "String payload value", HFILL }
       },
       { &hf_rbus_payload_int,
         { "Payload", "rbus.payload.int",
           FT_INT32, BASE_DEC, NULL, 0x0,
           "Integer payload value", HFILL }
       },
       { &hf_rbus_payload_uint,
         { "Payload", "rbus.payload.uint",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Unsigned integer payload value", HFILL }
       },
       { &hf_rbus_payload_int64,
         { "Payload", "rbus.payload.int64",
           FT_INT64, BASE_DEC, NULL, 0x0,
           "64-bit integer payload value", HFILL }
       },
       { &hf_rbus_payload_uint64,
         { "Payload", "rbus.payload.uint64",
           FT_UINT64, BASE_DEC, NULL, 0x0,
           "64-bit unsigned integer payload value", HFILL }
       },
       { &hf_rbus_payload_double,
         { "Payload", "rbus.payload.double",
           FT_DOUBLE, BASE_NONE, NULL, 0x0,
           "Double payload value", HFILL }
       },
       { &hf_rbus_payload_boolean,
         { "Payload", "rbus.payload.boolean",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           "Boolean payload value", HFILL }
       },
      /* RBus message structure fields */
      { &hf_rbus_session_id,
        { "Session ID", "rbus.session_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Session identifier for transactional operations", HFILL }
      },
      { &hf_rbus_component_name,
        { "Component Name", "rbus.component_name",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Name of the requesting component", HFILL }
      },
      { &hf_rbus_param_count,
        { "Parameter Count", "rbus.param_count",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of parameters in request", HFILL }
      },
      { &hf_rbus_property_count,
        { "Property Count", "rbus.property_count",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of properties in response", HFILL }
      },
      { &hf_rbus_error_code,
        { "Error Code", "rbus.error_code",
          FT_INT32, BASE_DEC, NULL, 0x0,
          "RBus error code from operation", HFILL }
      },
      { &hf_rbus_rollback,
        { "Rollback", "rbus.rollback",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Rollback flag for transactional operations", HFILL }
      },
      { &hf_rbus_commit,
        { "Commit", "rbus.commit",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Commit flag (TRUE/FALSE)", HFILL }
      },
      { &hf_rbus_parameter,
        { "Parameter", "rbus.parameter",
          FT_NONE, BASE_NONE, NULL, 0x0,
          "RBus parameter", HFILL }
      },
      { &hf_rbus_parameter_name,
        { "Name", "rbus.parameter.name",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Parameter name", HFILL }
      },
      { &hf_rbus_parameter_type,
        { "Type", "rbus.parameter.type",
          FT_UINT32, BASE_HEX, VALS(rbus_type_vals), 0x0,
          "Parameter type ID", HFILL }
      },
      { &hf_rbus_parameter_value_string,
        { "Value", "rbus.parameter.value.string",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Parameter string value", HFILL }
      },
      { &hf_rbus_parameter_value_int,
        { "Value", "rbus.parameter.value.int",
          FT_INT32, BASE_DEC, NULL, 0x0,
          "Parameter integer value", HFILL }
      },
      { &hf_rbus_parameter_value_uint,
        { "Value", "rbus.parameter.value.uint",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Parameter unsigned integer value", HFILL }
      },
      { &hf_rbus_parameter_value_int64,
        { "Value", "rbus.parameter.value.int64",
          FT_INT64, BASE_DEC, NULL, 0x0,
          "Parameter 64-bit integer value", HFILL }
      },
      { &hf_rbus_parameter_value_uint64,
        { "Value", "rbus.parameter.value.uint64",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Parameter 64-bit unsigned integer value", HFILL }
      },
      { &hf_rbus_parameter_value_double,
        { "Value", "rbus.parameter.value.double",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          "Parameter double value", HFILL }
      },
      { &hf_rbus_parameter_value_boolean,
        { "Value", "rbus.parameter.value.boolean",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Parameter boolean value", HFILL }
      },
      { &hf_rbus_property,
        { "Property", "rbus.property",
          FT_NONE, BASE_NONE, NULL, 0x0,
          "RBus property", HFILL }
      },
      { &hf_rbus_property_name,
        { "Name", "rbus.property.name",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Property name", HFILL }
      },
      { &hf_rbus_property_type,
        { "Type", "rbus.property.type",
          FT_UINT32, BASE_HEX, VALS(rbus_type_vals), 0x0,
          "Property type ID", HFILL }
      },
      { &hf_rbus_property_value_string,
        { "Value", "rbus.property.value.string",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Property string value", HFILL }
      },
      { &hf_rbus_property_value_int,
        { "Value", "rbus.property.value.int",
          FT_INT32, BASE_DEC, NULL, 0x0,
          "Property integer value", HFILL }
      },
      { &hf_rbus_property_value_uint,
        { "Value", "rbus.property.value.uint",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Property unsigned integer value", HFILL }
      },
      { &hf_rbus_property_value_int64,
        { "Value", "rbus.property.value.int64",
          FT_INT64, BASE_DEC, NULL, 0x0,
          "Property 64-bit integer value", HFILL }
      },
      { &hf_rbus_property_value_uint64,
        { "Value", "rbus.property.value.uint64",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          "Property 64-bit unsigned integer value", HFILL }
      },
      { &hf_rbus_property_value_double,
        { "Value", "rbus.property.value.double",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          "Property double value", HFILL }
      },
      { &hf_rbus_property_value_boolean,
        { "Value", "rbus.property.value.boolean",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Property boolean value", HFILL }
      },
      { &hf_rbus_failed_element,
        { "Failed Element", "rbus.failed_element",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Name of element that caused failure", HFILL }
      },
      { &hf_rbus_metadata,
        { "Metadata", "rbus.metadata",
          FT_NONE, BASE_NONE, NULL, 0x0,
          "RBus message metadata", HFILL }
      },
      { &hf_rbus_method_name,
        { "Method", "rbus.method",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "RBus method name", HFILL }
      },
      { &hf_rbus_ot_parent,
        { "OpenTelemetry Parent", "rbus.ot_parent",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "OpenTelemetry trace parent ID", HFILL }
      },
      { &hf_rbus_ot_state,
        { "OpenTelemetry State", "rbus.ot_state",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "OpenTelemetry trace state", HFILL }
      },
      { &hf_rbus_metadata_offset,
        { "Metadata Offset", "rbus.metadata.offset",
          FT_INT32, BASE_DEC, NULL, 0x0,
          "Byte offset to metadata start", HFILL }
      },
      { &hf_rbus_parameter_namevalue,
        { "Name=Value", "rbus.parameter.namevalue",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Parameter name and value combined for filtering (e.g., Device.WiFi.SSID.1.Enable=false)", HFILL }
      },
      { &hf_rbus_property_namevalue,
        { "Name=Value", "rbus.property.namevalue",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Property name and value combined for filtering (e.g., Device.WiFi.SSID.1.Enable=false)", HFILL }
      },
      { &hf_rbus_event_name,
        { "Event Name", "rbus.event_name",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Event being subscribed to or published", HFILL }
      },
      { &hf_rbus_reply_topic_payload,
        { "Reply Topic", "rbus.reply_topic_payload",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Reply topic in payload (for subscribe requests)", HFILL }
      },
      { &hf_rbus_invoke_method_name,
        { "Invoke Method Name", "rbus.invoke_method_name",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Name of method being invoked (RPC)", HFILL }
      },
      { &hf_rbus_has_params,
        { "Has Parameters", "rbus.has_params",
          FT_INT32, BASE_DEC, NULL, 0x0,
          "Indicates if parameters are present (1=yes, 0=no)", HFILL }
      },
      { &hf_rbus_event_type,
        { "Event Type", "rbus.event_type",
          FT_UINT32, BASE_DEC, VALS(rbus_event_type_vals), 0x0,
          "Type of RBus event", HFILL }
      },
      { &hf_rbus_has_event_data,
        { "Has Event Data", "rbus.has_event_data",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Indicates if event data is present", HFILL }
      },
      { &hf_rbus_event_data,
        { "Event Data", "rbus.event_data",
          FT_NONE, BASE_NONE, NULL, 0x0,
          "RBus event data (rbusObject)", HFILL }
      },
      { &hf_rbus_has_filter,
        { "Has Filter", "rbus.has_filter",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Indicates if a filter is present", HFILL }
      },
      { &hf_rbus_interval,
        { "Interval", "rbus.interval",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Event publication interval (milliseconds)", HFILL }
      },
      { &hf_rbus_duration,
        { "Duration", "rbus.duration",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Event subscription duration (seconds)", HFILL }
      },
      { &hf_rbus_component_id,
        { "Component ID", "rbus.component_id",
          FT_INT32, BASE_DEC, NULL, 0x0,
          "Component identifier", HFILL }
      },
      { &hf_rbus_object_property,
        { "Property", "rbus.object.property",
          FT_NONE, BASE_NONE, NULL, 0x0,
          "Event data property", HFILL }
      },
      { &hf_rbus_object_property_name,
        { "Name", "rbus.object.property.name",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Event data property name", HFILL }
      },
      { &hf_rbus_object_property_namevalue,
        { "Name=Value", "rbus.object.property.namevalue",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "Event data property name and value for filtering", HFILL }
      },
   };

   static gint* ett[] = {
       &ett_rbus,
       &ett_rbus_header,
       &ett_rbus_payload,
       &ett_rbus_flags,
       &ett_rbus_parameter,
       &ett_rbus_property,
       &ett_rbus_metadata,
   };

   static ei_register_info ei[] = {
           { &ei_rbus_invalid_length,
               { "rbus.invalid_length", PI_MALFORMED, PI_ERROR,
                   "Invalid length field", EXPFILL }
           },
           { &ei_rbus_malformed_header,
               { "rbus.malformed_header", PI_MALFORMED, PI_ERROR,
                   "Malformed message header", EXPFILL }
           },
           { &ei_rbus_truncated_packet,
               { "rbus.truncated", PI_MALFORMED, PI_WARN,
                   "Packet is truncated", EXPFILL }
           },
           { &ei_rbus_msgpack_depth_exceeded,
               { "rbus.msgpack_depth_exceeded", PI_MALFORMED, PI_WARN,
                   "MessagePack depth limit exceeded", EXPFILL }
           },
   };

   expert_module_t* expert_rbus;
   module_t* rbus_module;

   /* Register protocol */
   proto_rbus = proto_register_protocol(
      RBUS_PROTOCOL_LONG_NAME,    /* Full name */
      RBUS_PROTOCOL_SHORT_NAME,   /* Short name */
      RBUS_PROTOCOL_NAME          /* Filter name */
   );

   /* Register fields and subtrees */
   proto_register_field_array(proto_rbus, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   /* Register expert info */
   expert_rbus = expert_register_protocol(proto_rbus);
   expert_register_field_array(expert_rbus, ei, array_length(ei));

   /* Register preferences */
   rbus_module = prefs_register_protocol(proto_rbus, NULL);

   prefs_register_uint_preference(rbus_module, "tcp_port",
      "TCP Port",
      "TCP port for RBus protocol",
      10, &pref_tcp_port);

   prefs_register_uint_preference(rbus_module, "msgpack_depth_limit",
      "MessagePack Depth Limit",
      "Maximum nesting depth for MessagePack decoding",
      10, &pref_msgpack_depth_limit);

   prefs_register_uint_preference(rbus_module, "msgpack_object_limit",
      "MessagePack Object Limit",
      "Maximum number of MessagePack objects to decode per payload",
      10, &pref_msgpack_object_limit);
}

/*
 * Register protocol handoff
 */
void
proto_reg_handoff_rbus(void) {
   /* Create dissector handle */
   rbus_handle = create_dissector_handle(dissect_rbus, proto_rbus);

   /* Register as heuristic dissector for TCP */
   heur_dissector_add("tcp", dissect_rbus_heur, "RBus over TCP",
      "rbus_tcp", proto_rbus, HEURISTIC_ENABLE);

   /* Register for default TCP port */
   dissector_add_uint("tcp.port", pref_tcp_port, rbus_handle);
}

/*
 * Plugin registration entry point - called by Wireshark to initialize the plugin
 */
WS_DLL_PUBLIC void
plugin_register(void) {
   static proto_plugin plug_rbus;

   plug_rbus.register_protoinfo = proto_register_rbus;
   plug_rbus.register_handoff = proto_reg_handoff_rbus;
   proto_register_plugin(&plug_rbus);
}
