add_executable(tesla_node_agent
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_node_agent
    PRIVATE
        Threads::Threads
        tesla_core
        tesla_metrics
        tesla_workload
)

set_target_properties(tesla_node_agent
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Applications"
)
