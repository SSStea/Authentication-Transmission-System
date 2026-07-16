qt_add_executable(tesla_manager_gui
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_manager_gui
    PRIVATE
        Qt6::Charts
        Qt6::Core
        Qt6::Network
        Qt6::Widgets
        tesla_crypto
        tesla_metrics
        tesla_protocol
        tesla_workload
)

set_target_properties(tesla_manager_gui
    PROPERTIES
        FOLDER "Applications"
        WIN32_EXECUTABLE TRUE
)
