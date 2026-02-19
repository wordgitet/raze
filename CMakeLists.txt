cmake_minimum_required(VERSION 3.16)
project(raze C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(RAZE_USE_ISAL "Use bundled ISA-L if available" ON)

file(GLOB_RECURSE RAZE_SRCS CONFIGURE_DEPENDS "src/*.c")

add_executable(raze ${RAZE_SRCS})
target_include_directories(raze PRIVATE include)

if(MSVC)
	target_compile_options(raze PRIVATE /W4)
else()
	target_compile_options(raze PRIVATE -Wall -Wextra -Wpedantic)
endif()

find_package(OpenSSL)
if(OpenSSL_FOUND)
	target_compile_definitions(raze PRIVATE RAZE_HAVE_OPENSSL=1)
	target_link_libraries(raze PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(RAZE_USE_ISAL)
	set(ISAL_LIB "${CMAKE_SOURCE_DIR}/third_party/isa-l/bin/isa-l.a")
	if(EXISTS "${ISAL_LIB}")
		target_compile_definitions(raze PRIVATE RAZE_USE_ISAL=1)
		target_include_directories(raze PRIVATE
			"${CMAKE_SOURCE_DIR}/third_party/isa-l/include")
		target_link_libraries(raze PRIVATE "${ISAL_LIB}")
	endif()
endif()
