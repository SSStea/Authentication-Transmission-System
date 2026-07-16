qt_add_executable(tesla_uav_monitor_gui
    UavMonitorMainWindow.cpp
    UavMonitorMainWindow.h
    UavMonitorNetworkController.cpp
    UavMonitorNetworkController.h
    main.cpp
    CMakeLists.txt
)

source_group("Header Files" FILES
    UavMonitorMainWindow.h
    UavMonitorNetworkController.h
)
source_group("Source Files" FILES
    UavMonitorMainWindow.cpp
    UavMonitorNetworkController.cpp
    main.cpp
)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_uav_monitor_gui
    PRIVATE
        Qt6::Charts
        Qt6::Core
        Qt6::Network
        Qt6::Widgets
        tesla_metrics
        tesla_protocol
)

set_target_properties(tesla_uav_monitor_gui
    PROPERTIES
        FOLDER "Applications"
        WIN32_EXECUTABLE TRUE
)
