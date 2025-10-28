cmake_minimum_required(VERSION 4.1)

project(REFLECTIVELOADER VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -flto")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -flto")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")

add_executable(loader src/main.c src/util.c src/local.c src/remote.c)
target_include_directories(loader PRIVATE include)

