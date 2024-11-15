cmake_minimum_required(VERSION 3.10)
project(RouterEx C)

# Set the C standard
set(CMAKE_C_STANDARD 11)

# Set build type to Debug (automatically adds -g)
set(CMAKE_BUILD_TYPE Debug)

# Add compiler options
add_compile_options(-std=c11)

# Include libpatricia headers and add it as a static library
include_directories(${CMAKE_SOURCE_DIR}/common/libpatricia)
add_library(patricia STATIC
    ${CMAKE_SOURCE_DIR}/common/libpatricia/patricia.c
)

# Include libevent headers
include_directories(/usr/local/include)

# Find libevent libraries
find_library(EVENT_LIB event PATHS /usr/local/lib)
find_library(EVENT_CORE_LIB event_core PATHS /usr/local/lib)
find_library(EVENT_EXTRA_LIB event_extra PATHS /usr/local/lib)
find_library(EVENT_PTHREADS_LIB event_pthreads PATHS /usr/local/lib)

# Add the executable
add_executable(RouterEx router.c)

# Link against libpatricia and libevent libraries
target_link_libraries(RouterEx
    patricia
    ${EVENT_LIB}
    ${EVENT_CORE_LIB}
    ${EVENT_EXTRA_LIB}
    ${EVENT_PTHREADS_LIB}
)

# Debug output for library paths (optional)
message("Library paths: ${CMAKE_LIBRARY_PATH}")
