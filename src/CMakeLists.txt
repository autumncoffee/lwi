project(lwi)

cmake_minimum_required(VERSION 3.10)

set(AC_COMMON_CXX_FLAGS "-std=c++17")
set(AC_DEBUG_CXX_FLAGS "")

if("$ENV{IS_DEV}" STREQUAL "1")
    set(AC_TCMALLOC_CXX_FLAGS "")
    set(AC_DEBUG_CXX_FLAGS "-g")

    set(CMAKE_EXE_LINKER_FLAGS "-g -fsanitize=address ${CMAKE_EXE_LINKER_FLAGS}")
    add_compile_options("-fsanitize=address")

else()
    add_compile_options("-O3")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${AC_COMMON_CXX_FLAGS} ${AC_DEBUG_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

file(GLOB AC_LWI_SOURCES *.cpp)

include_directories("../ac")
include_directories(".")

add_subdirectory("../ac/ac-common" ac_common_bindir)

add_executable(lwi ${AC_LWI_SOURCES})

target_link_libraries(
    lwi
    ac_common
    "-lstdc++fs"
)

install(TARGETS lwi RUNTIME DESTINATION bin)
