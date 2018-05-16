cmake_minimum_required(VERSION 2.8.11)


include_directories(src kernel-headers kernel-headers/uapi)

add_library(devx
	src/devx.c
	src/devx_dbrec.c
	src/devx_init.c
	src/devx_ioctl.c
	src/devx_uar.c)

add_subdirectory(googletest/googletest)

add_executable(test tests/test.cc)

target_link_libraries(test devx gtest gtest_main)

project (devx)
set(VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "devx")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "support@mellanox.com")
set(CPACK_PACKAGE_VENDOR "Mellanox")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)
