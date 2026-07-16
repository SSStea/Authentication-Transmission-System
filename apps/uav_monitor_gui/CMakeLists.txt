qt_add_executable(tesla_uav_monitor_gui
    main.cpp
)

target_link_libraries(tesla_uav_monitor_gui
    PRIVATE
        Qt6::Charts
        Qt6::Core
        Qt6::Network
        Qt6::Widgets
        tesla_metrics
        tesla_protocol
)

set_target_properties(tesla_uav_monitor_gui PROPERTIES WIN32_EXECUTABLE TRUE)
