cmake_minimum_required(VERSION 2.8.11)

include_directories(src kernel-headers kernel-headers/uapi)

add_library(devx
	src/devx.c
	src/devx_dbrec.c
	src/devx_init.c
	src/devx_ioctl.c
	src/devx_uar.c)

add_subdirectory(googletest/googletest)

add_executable(test
	tests/test.cc)

target_link_libraries(test devx gtest gtest_main)
