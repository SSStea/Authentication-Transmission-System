cmake_minimum_required(VERSION 3.24)

project(AuthenticationTransmissionSystem VERSION 0.1.0 LANGUAGES CXX)

option(BUILD_GUI "Build the four Qt GUI applications" ON)
option(BUILD_TESTING "Build the automated test executables" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC defaults to the system code page, so explicitly compile UTF-8 source comments.
if(MSVC)
    add_compile_options(/utf-8)
endif()

# Keep generated Visual Studio solutions focused on reviewable product targets.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "CMake")

if(BUILD_TESTING)
    enable_testing()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# 控制面只在协议边界使用JSON；固定版本和校验值保证各平台得到相同依赖。
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

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

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
