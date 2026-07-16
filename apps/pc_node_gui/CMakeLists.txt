qt_add_executable(tesla_pc_node_gui
    PcNodeMainWindow.cpp
    PcNodeMainWindow.h
    PcNodeNetworkController.cpp
    PcNodeNetworkController.h
    main.cpp
    CMakeLists.txt
)

source_group("Header Files" FILES
    PcNodeMainWindow.h
    PcNodeNetworkController.h
)
source_group("Source Files" FILES
    PcNodeMainWindow.cpp
    PcNodeNetworkController.cpp
    main.cpp
)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_pc_node_gui
    PRIVATE
        Qt6::Charts
        Qt6::Core
        Qt6::Network
        Qt6::Widgets
        tesla_core
        tesla_metrics
        tesla_protocol
        tesla_workload
)

set_target_properties(tesla_pc_node_gui
    PROPERTIES
        FOLDER "Applications"
        WIN32_EXECUTABLE TRUE
)
