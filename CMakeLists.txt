cmake_minimum_required(VERSION 3.24)

project(AuthenticationTransmissionSystem VERSION 0.1.0 LANGUAGES CXX)

option(BUILD_GUI "Build the four Qt GUI applications" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if(BUILD_GUI)
    find_package(Qt6 REQUIRED COMPONENTS Core Network Widgets Charts)
    qt_standard_project_setup()
endif()

add_subdirectory(common/protocol)
add_subdirectory(common/crypto)
add_subdirectory(common/tesla)
add_subdirectory(common/workload)
add_subdirectory(common/metrics)

add_subdirectory(apps/node_agent)

if(BUILD_GUI)
    add_subdirectory(apps/manager_gui)
    add_subdirectory(apps/pc_node_gui)
    add_subdirectory(apps/uav_monitor_gui)
    add_subdirectory(apps/attack_test_gui)
endif()

add_subdirectory(tests)
