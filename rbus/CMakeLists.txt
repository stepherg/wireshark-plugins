cmake_minimum_required(VERSION 3.10)
project(rbus-wireshark-dissector VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC -Wno-typedef-redefinition")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

# Find required packages
find_package(PkgConfig REQUIRED)

# Find Wireshark
find_package(Wireshark CONFIG)

# If find_package found Wireshark but didn't populate include dirs, or if it didn't find it at all,
# fall back to pkg-config
if(NOT Wireshark_FOUND OR NOT Wireshark_INCLUDE_DIRS)
    # Try pkg-config
    pkg_check_modules(WIRESHARK wireshark>=3.0.0)
    if(NOT WIRESHARK_FOUND)
        message(FATAL_ERROR "Wireshark development headers not found. Install wireshark-dev or wireshark-devel package.")
    endif()
    
    # Get include dirs manually from pkg-config since pkg_check_modules doesn't always populate them correctly
    execute_process(
        COMMAND pkg-config --cflags-only-I wireshark
        OUTPUT_VARIABLE WIRESHARK_INCLUDE_FLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    message(STATUS "Raw include flags from pkg-config: ${WIRESHARK_INCLUDE_FLAGS}")
    
    # Convert -I flags to list of directories
    string(REPLACE " " ";" WIRESHARK_INCLUDE_LIST "${WIRESHARK_INCLUDE_FLAGS}")
    set(WIRESHARK_INCLUDE_DIRS_LIST "")
    foreach(FLAG ${WIRESHARK_INCLUDE_LIST})
        string(REGEX REPLACE "^-I" "" INCLUDE_DIR "${FLAG}")
        if(INCLUDE_DIR)
            list(APPEND WIRESHARK_INCLUDE_DIRS_LIST "${INCLUDE_DIR}")
        endif()
    endforeach()
    
    message(STATUS "Parsed include dirs: ${WIRESHARK_INCLUDE_DIRS_LIST}")
    
    # Set variables from pkg-config
    set(Wireshark_INCLUDE_DIRS ${WIRESHARK_INCLUDE_DIRS_LIST})
    set(Wireshark_LIBRARY_DIRS ${WIRESHARK_LIBRARY_DIRS})
    set(Wireshark_LIBRARIES ${WIRESHARK_LIBRARIES})
    set(Wireshark_LDFLAGS ${WIRESHARK_LDFLAGS})
    
    # Get version if not already set
    if(NOT Wireshark_VERSION)
        execute_process(
            COMMAND pkg-config --modversion wireshark
            OUTPUT_VARIABLE Wireshark_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif()
    
    # Get all compile flags
    set(Wireshark_COMPILE_FLAGS ${WIRESHARK_CFLAGS})
    
    # Try to find plugin directory if not already set
    if(NOT WIRESHARK_PLUGIN_DIR)
        execute_process(
            COMMAND pkg-config --variable=plugindir wireshark
            OUTPUT_VARIABLE WIRESHARK_PLUGIN_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif()
    
    if(NOT WIRESHARK_PLUGIN_DIR)
        # Fallback to user's personal plugin directory
        # Protocol dissectors go in the epan subdirectory
        if(APPLE)
            # Get Wireshark major-minor version for plugin subdirectory
            string(REGEX MATCH "^([0-9]+\\.[0-9]+)" WS_VERSION_SHORT "${Wireshark_VERSION}")
            string(REPLACE "." "-" WS_VERSION_SHORT "${WS_VERSION_SHORT}")
            set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins/${WS_VERSION_SHORT}/epan")
        else()
            set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins/epan")
        endif()
    endif()
else()
    # find_package succeeded, use its variables but still might need plugin dir
    if(NOT WIRESHARK_PLUGIN_DIR)
        if(Wireshark_PLUGIN_INSTALL_DIR)
            set(WIRESHARK_PLUGIN_DIR "${Wireshark_PLUGIN_INSTALL_DIR}")
        else()
            execute_process(
                COMMAND pkg-config --variable=plugindir wireshark
                OUTPUT_VARIABLE WIRESHARK_PLUGIN_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            # If pkg-config doesn't provide it, use user's directory
            if(NOT WIRESHARK_PLUGIN_DIR AND APPLE)
                string(REGEX MATCH "^([0-9]+\\.[0-9]+)" WS_VERSION_SHORT "${Wireshark_VERSION}")
                string(REPLACE "." "-" WS_VERSION_SHORT "${WS_VERSION_SHORT}")
                set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins/${WS_VERSION_SHORT}/epan")
            endif()
        endif()
    endif()
    set(Wireshark_COMPILE_FLAGS "")
endif()

if(APPLE)
   string(REGEX MATCH "^([0-9]+\\.[0-9]+)" WS_VERSION_SHORT "${Wireshark_VERSION}")
   string(REPLACE "." "-" WS_VERSION_SHORT "${WS_VERSION_SHORT}")
   set(WIRESHARK_USER_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins/${WS_VERSION_SHORT}/epan")
endif()

message(STATUS "Wireshark version: ${Wireshark_VERSION}")
message(STATUS "Wireshark include dirs: ${Wireshark_INCLUDE_DIRS}")
message(STATUS "Wireshark compile flags: ${Wireshark_COMPILE_FLAGS}")
message(STATUS "Wireshark plugin directory: ${WIRESHARK_PLUGIN_DIR}")
message(STATUS "Wireshark user plugin directory: ${WIRESHARK_USER_PLUGIN_DIR}")

# Find GLib
pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.32.0)
if(NOT GLIB2_FOUND)
    message(FATAL_ERROR "GLib 2.0 not found. Install libglib2.0-dev package.")
endif()

message(STATUS "GLib version: ${GLIB2_VERSION}")
message(STATUS "GLib include dirs: ${GLIB2_INCLUDE_DIRS}")

# Find MessagePack
pkg_check_modules(MSGPACK msgpackc msgpack)
if(NOT MSGPACK_FOUND)
    # Try to find it manually
    find_path(MSGPACK_INCLUDE_DIR msgpack.h PATH_SUFFIXES msgpack)
    find_library(MSGPACK_LIBRARY NAMES msgpackc msgpack)
    
    if(MSGPACK_INCLUDE_DIR AND MSGPACK_LIBRARY)
        set(MSGPACK_FOUND TRUE)
        set(MSGPACK_INCLUDE_DIRS ${MSGPACK_INCLUDE_DIR})
        set(MSGPACK_LIBRARIES ${MSGPACK_LIBRARY})
        message(STATUS "MessagePack found manually")
    else()
        message(WARNING "MessagePack not found. Install libmsgpack-dev or msgpack-devel package.")
        message(WARNING "Building without MessagePack support - payload decoding will be limited.")
        set(MSGPACK_FOUND FALSE)
    endif()
endif()

if(MSGPACK_FOUND)
    message(STATUS "MessagePack include dirs: ${MSGPACK_INCLUDE_DIRS}")
    message(STATUS "MessagePack libraries: ${MSGPACK_LIBRARIES}")
    add_definitions(-DHAVE_MSGPACK)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Add Wireshark include directories from pkg-config
if(Wireshark_INCLUDE_DIRS)
    include_directories(${Wireshark_INCLUDE_DIRS})
endif()

include_directories(${GLIB2_INCLUDE_DIRS})

if(MSGPACK_FOUND)
    include_directories(${MSGPACK_INCLUDE_DIRS})
endif()

# Source files
set(DISSECTOR_SOURCES
    src/packet-rbus.c
)

# Create the dissector plugin as a shared library
add_library(rbus MODULE ${DISSECTOR_SOURCES})

# Add Wireshark compile flags (includes -I flags for headers)
if(Wireshark_COMPILE_FLAGS)
    # Convert to list and apply
    separate_arguments(WS_CFLAGS UNIX_COMMAND "${Wireshark_COMPILE_FLAGS}")
    target_compile_options(rbus PRIVATE ${WS_CFLAGS})
endif()

# Set output name (Wireshark expects specific naming)
set_target_properties(rbus PROPERTIES
    PREFIX ""
    OUTPUT_NAME "rbus"
    SUFFIX ".so"
    # Allow undefined symbols - they will be resolved when loaded by Wireshark
    LINK_FLAGS "-undefined dynamic_lookup"
)

# Link libraries
# Note: Wireshark plugins don't link against libwireshark; they are loaded as modules
# Use the full LDFLAGS from pkg-config which include library paths
target_link_libraries(rbus
    ${GLIB2_LDFLAGS}
)

if(MSGPACK_FOUND)
    target_link_libraries(rbus ${MSGPACK_LIBRARIES})
endif()

# Installation
install(TARGETS rbus
   LIBRARY DESTINATION ${WIRESHARK_PLUGIN_DIR}
   LIBRARY DESTINATION ${WIRESHARK_USER_PLUGIN_DIR}
)

# Print installation instructions
message(STATUS "")
message(STATUS "======================================")
message(STATUS "Build configuration complete!")
message(STATUS "")
message(STATUS "To build and install:")
message(STATUS "  make")
message(STATUS "  make install")
message(STATUS "")
message(STATUS "Plugin will be installed to:")
message(STATUS "  ${WIRESHARK_PLUGIN_DIR}")
message(STATUS "  ${WIRESHARK_USER_PLUGIN_DIR}")
message(STATUS "======================================")
message(STATUS "")

# Testing support (optional)
option(BUILD_TESTS "Build test utilities" OFF)
if(BUILD_TESTS)
    add_subdirectory(test)
endif()
