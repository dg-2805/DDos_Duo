cmake_minimum_required(VERSION 3.10)
project(aiori)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Find Core Dependencies ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(LDNS REQUIRED ldns)
find_package(Threads REQUIRED)

# --- Find CURL ---
find_package(CURL REQUIRED)  # Changed to REQUIRED

# --- Find Boost ---  
find_package(Boost REQUIRED)  # Changed to REQUIRED

# --- Find or Fetch JSON Library ---
# First try to find system nlohmann_json
find_package(nlohmann_json 3.2.0 QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found in system, using FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.2
    )
    FetchContent_MakeAvailable(nlohmann_json)
else()
    message(STATUS "Found system nlohmann_json")
endif()

# --- Add Executable ---
add_executable(aiori
    src/main/dns-idk.cpp
    #src/main/dnsbalancer.cpp
    src/config/config_loader.cpp
    src/config/health_checker.cpp
)

# --- Compiler Options and Includes ---
target_compile_options(aiori PRIVATE -Wall -Wextra -O2)
target_include_directories(aiori PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LDNS_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

# --- Link Libraries ---
target_link_libraries(aiori PRIVATE
    ${LDNS_LIBRARIES}
    ${Boost_LIBRARIES}
    ${CURL_LIBRARIES}
    Threads::Threads
    nlohmann_json::nlohmann_json
)

# --- Linker Flags ---
target_link_options(aiori PRIVATE ${LDNS_LDFLAGS})

# --- Copy Config File ---
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/config/config.json
    ${CMAKE_CURRENT_BINARY_DIR}/config.json
    COPYONLY
)