cmake_minimum_required (VERSION 2.8)

project("libPSI")


set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)


#############################################
#            Flag and #defines              #
#############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")

# set(CMAKE_CONFIGURATION_TYPES "Debug")
set(CMAKE_BUILD_TYPE "Debug")

# Set a default build type for single-configuration
# CMake generators if no build type is set.
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()

if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with CMAKE_BUILD_TYPE=Release")
endif()

# Select flags.
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
SET(CMAKE_CXX_FLAGS_DEBUG  "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")


#############################################
#       Library/includes locations          #
#############################################

# default location for libOTe
set(libOTe_Dirs "${CMAKE_SOURCE_DIR}/libOTe/")
include_directories("${libOTe_Dirs}/libOTe/") 
link_directories("${libOTe_Dirs}/lib/")

# default location for miracl
set(Miracl_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}") 
link_directories("${Miracl_Dirs}/miracl/source/")

# default location for NTL
set(NTL_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/ntl/")
include_directories("${NTL_Dirs}/include/")
link_directories("${NTL_Dirs}/src/") 

# default location for Boost
set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/linux/boost/")


#############################################
#            Build cryptoTools              #
#############################################
add_subdirectory(cryptoTools)
include_directories(cryptoTools)

#############################################
#               Build libOTe                #
#############################################
add_subdirectory(libOTe)
include_directories(libOTe)


#############################################
#               Build libOPRF                 #
#############################################
add_subdirectory(libOPRF)
include_directories(libOPRF)


#############################################
#           Build libPSI Tests              #
#############################################
#add_subdirectory(libPSI_Tests)
#include_directories(libPSI_Tests)


#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)
include_directories(frontend)

