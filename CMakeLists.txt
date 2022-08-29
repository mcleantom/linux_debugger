cmake_minimum_required(VERSION 3.0)
project(MiniDbg)

add_compile_definitions(-std=c++14)

include_directories(ext/libelfin ext/linenoise include)
add_executable(minnidbg src/minidbg ext/linenoise/linenoise.c)

add_executable(hellp examples/example1.cpp)