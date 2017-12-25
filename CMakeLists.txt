cmake_minimum_required(VERSION 3.9)
project(perf-map-agent)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

include_directories(src)

find_package(JNI)
INCLUDE_DIRECTORIES(${JAVA_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${JAVA_INCLUDE_PATH2})

add_library(perfmap SHARED src/agent.cpp)
