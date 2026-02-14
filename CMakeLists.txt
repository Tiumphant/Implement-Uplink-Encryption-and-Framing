cmake_minimum_required(VERSION 3.16)
project(lorawan_crypto)

set(CMAKE_CXX_STANDARD 20)

include_directories(include)

find_package(OpenSSL REQUIRED)

add_library(core
    src/Crypto.cpp
    src/FrameCounter.cpp
    src/LoRaPayload.cpp
)

target_link_libraries(core OpenSSL::SSL OpenSSL::Crypto)

add_executable(tests tests/test_crypto.cpp)
target_link_libraries(tests core gtest gtest_main pthread)
