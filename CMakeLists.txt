#----------------------------------------------
#	root CMakeList.txt for network-platfrom
#	Author: jiangxiaoyu
#	Date: Sat May 6 2023
#----------------------------------------------

# Disable in-source builds to prevent source tree corruption.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	 message(FATAL_ERROR "FATAL: In-source builds are not allowed.
        You should create a separate directory for build files.")
endif()

cmake_minimum_required(VERSION 3.0.0)

if(POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

PROJECT(network-platfrom)

SET(CMAKE_BUILD_TYPE Release)

SET(PRO_TOP_PATH "${PROJECT_SOURCE_DIR}")

# Find includes in corresponding build directories
SET(CMAKE_INCLUDE_CURRENT_DIR ON)

# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# set  xxx.cmake path
#SET(CMAKE_PREFIX_PATH "/opt/Qt5.12.12/5.12.12/gcc_64/lib/cmake")
#SET(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${CMAKE_CURRENT_SOURCE_DIR}")


#添加C++11支持及其他选项
SET(CMAKE_CXX_FLAGS "-std=c++0x ${CMAKE_CXX_FLAGS} -g -ftest-coverage -fprofile-arcs -Wno-deprecated")
SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY )
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ./out)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ./out)

# fingure out where will be installing with prefix
#SET(CMAKE_INSTALL_LIBDIR "/usr/local/lib/vircloud-manage")
# use, i.e. don't skip the full RPATH for the build tree
set(CMAKE_SKIP_BUILD_RPATH FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)


# the RPATH to be used when installing, but only if it's not a system directory
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_LIBDIR}" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}")
endif("${isSystemDir}" STREQUAL "-1")


# add sub directory
ADD_SUBDIRECTORY(src)

