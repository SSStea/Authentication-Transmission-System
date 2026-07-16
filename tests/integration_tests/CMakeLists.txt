add_executable(tesla_node_agent_network_tests
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_node_agent_network_tests
    PRIVATE
        tesla_node_agent_runtime
)

set_target_properties(tesla_node_agent_network_tests
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Tests"
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME tesla_node_agent_network_tests COMMAND tesla_node_agent_network_tests)
    set_tests_properties(tesla_node_agent_network_tests PROPERTIES TIMEOUT 15 RUN_SERIAL TRUE)
endif()
