
# Find the QtWidgets library
find_package(Qt5Xml)
find_package(Qt5Widgets)
find_package(Qt5Core)


# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)
# Instruct CMake to run uic automatically when needed.
set(CMAKE_AUTOUIC ON)

 
# add C++11 support and options
set(CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS} -g -ftest-coverage -lpthread -fprofile-arcs -Wno-deprecated")

#add source directrory
aux_source_directory(. SRCS)

# Tell CMake to create the virtsysManage executable
add_executable(ntmg socket-manage.cpp)
add_executable(ping_c ping.cpp)

#add header files directory and libs for target 
target_link_libraries(ntmg pthread)
