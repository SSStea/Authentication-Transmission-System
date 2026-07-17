set(TESLA_NODE_AGENT_HEADERS
    include/tesla/node_agent/NetworkInterfaceSelector.h
    include/tesla/node_agent/NodeAgentConfig.h
    include/tesla/node_agent/NodeAgentService.h
    include/tesla/node_agent/SystemTimeSynchronization.h
    include/tesla/node_agent/TcpManagementServer.h
    include/tesla/node_agent/UdpDiscoveryService.h
    include/tesla/node_agent/UdpMulticastChannel.h
)

set(TESLA_NODE_AGENT_POSIX_SOURCES
    src/NetworkInterfaceSelector.cpp
    src/NodeAgentService.cpp
    src/SystemTimeSynchronization.cpp
    src/TcpManagementServer.cpp
    src/UdpDiscoveryService.cpp
    src/UdpMulticastChannel.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(TESLA_NODE_AGENT_PLATFORM_SOURCES ${TESLA_NODE_AGENT_POSIX_SOURCES})
else()
    # POSIX实现仍显示在Visual Studio项目中，但只在Linux目标上参与编译。
    set_source_files_properties(${TESLA_NODE_AGENT_POSIX_SOURCES} PROPERTIES HEADER_FILE_ONLY TRUE)
    set(TESLA_NODE_AGENT_PLATFORM_SOURCES
        ${TESLA_NODE_AGENT_POSIX_SOURCES}
        src/WindowsReviewStub.cpp
    )
endif()

add_library(tesla_node_agent_runtime STATIC
    ${TESLA_NODE_AGENT_HEADERS}
    ${TESLA_NODE_AGENT_PLATFORM_SOURCES}
    CMakeLists.txt
)

source_group("Header Files" FILES ${TESLA_NODE_AGENT_HEADERS})
source_group("Source Files" FILES ${TESLA_NODE_AGENT_POSIX_SOURCES})
source_group("Build Files" FILES CMakeLists.txt)

target_include_directories(tesla_node_agent_runtime
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(tesla_node_agent_runtime
    PUBLIC
        Threads::Threads
        tesla_core
)

target_compile_features(tesla_node_agent_runtime PUBLIC cxx_std_17)

set_target_properties(tesla_node_agent_runtime
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Applications/NodeAgent"
)

add_executable(tesla_node_agent
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_node_agent
    PRIVATE
        tesla_node_agent_runtime
        tesla_metrics
        tesla_workload
)

set_target_properties(tesla_node_agent
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Applications/NodeAgent"
)
