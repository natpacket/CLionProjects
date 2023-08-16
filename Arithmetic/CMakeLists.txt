cmake_minimum_required(VERSION 3.26)
project(Arithmetic)

set(CMAKE_CXX_STANDARD 11)

add_executable(arithmetic main.cpp
        base64.cpp
        base64.h
        md5.cpp
        md5.h
        sha1.cpp
        sha1.h
        hmac_md5.cpp
        hmac_md5.h
        crc32.cpp
        crc32.h
)
