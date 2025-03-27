cmake_minimum_required(VERSION 3.25)
project(libdecomp VERSION 0.1 LANGUAGES C)

option(LIBDECOMP_BUILD_EXAMPLES "Build example programs" OFF)
option(LIBDECOMP_BUILD_SHARED_LIB "Build shared library" OFF)

set(LIB_TYPE STATIC)
if(LIBDECOMP_BUILD_SHARED_LIB)
    set(LIB_TYPE SHARED)
endif()

add_compile_options(-g)

configure_file(version.h.in version.h)
include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB_RECURSE LIBDECOMP_GLOB_SRC CONFIGURE_DEPENDS "libdecomp/*.c")
file(GLOB_RECURSE LIBDECOMP_GLOB_HDR CONFIGURE_DEPENDS "include/*.h")

add_library(decomp ${LIB_TYPE} ${LIBDECOMP_GLOB_SRC})
target_link_libraries(decomp)
target_include_directories(decomp PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_target_properties(decomp PROPERTIES VERSION ${PROJECT_VERSION})

install(TARGETS decomp
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)

install(
    DIRECTORY ${CMAKE_SOURCE_DIR}/include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h*")

if (LIBDECOMP_BUILD_EXAMPLES)
    include(FetchContent)

    find_package(Zydis QUIET)
    if (NOT Zydis_FOUND)
        FetchContent_Declare(
            Zydis
            GIT_REPOSITORY https://github.com/zyantific/zydis.git
            GIT_TAG v4.1.0
        )

        FetchContent_MakeAvailable(Zydis)
    endif()

    find_package(capstone QUIET)
    if (NOT capstone_FOUND)
        FetchContent_Declare(
            capstone
            GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
            GIT_TAG 5.0.6
        )

        FetchContent_MakeAvailable(capstone)
    endif()

    add_executable(decomp-cli examples/decomp-cli/main.c)
    target_link_libraries(decomp-cli decomp capstone)
    
    add_executable(expr_test examples/expr_test/main.c)
    target_link_libraries(expr_test decomp capstone)
    
    add_executable(memory_fmt examples/memory_fmt/main.c)
    target_link_libraries(memory_fmt decomp Zydis capstone)
    
    add_executable(simple examples/simple/main.c)
    target_link_libraries(simple decomp Zydis)
    
    add_executable(simple_capstone examples/simple_capstone/main.c)
    target_link_libraries(simple_capstone decomp capstone)
    
    add_executable(simple_capstone_arm64 examples/simple_capstone_arm64/main.c)
    target_link_libraries(simple_capstone_arm64 decomp capstone)
endif()
