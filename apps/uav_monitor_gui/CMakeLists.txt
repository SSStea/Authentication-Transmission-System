qt_add_executable(tesla_uav_monitor_gui
    AuthenticationMetricsView.cpp
    AuthenticationMetricsView.h
    UavMonitorMainWindow.cpp
    UavMonitorMainWindow.h
    UavMonitorNetworkController.cpp
    UavMonitorNetworkController.h
    main.cpp
    CMakeLists.txt
)

source_group("Header Files" FILES
    AuthenticationMetricsView.h
    UavMonitorMainWindow.h
    UavMonitorNetworkController.h
)
source_group("Source Files" FILES
    AuthenticationMetricsView.cpp
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
        tesla_core
        tesla_common_gui
)

set_target_properties(tesla_uav_monitor_gui
    PROPERTIES
        FOLDER "Applications"
        WIN32_EXECUTABLE TRUE
)
