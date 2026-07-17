qt_add_executable(tesla_manager_gui
    ManagerAttackExperimentController.cpp
    ManagerAttackExperimentController.h
    ManagerAuthenticationController.cpp
    ManagerAuthenticationController.h
    ManagerMainWindow.cpp
    ManagerMainWindow.h
    ManagerNetworkController.cpp
    ManagerNetworkController.h
    main.cpp
    CMakeLists.txt
)

source_group("Header Files" FILES
    ManagerAttackExperimentController.h
    ManagerAuthenticationController.h
    ManagerMainWindow.h
    ManagerNetworkController.h
)
source_group("Source Files" FILES
    ManagerAttackExperimentController.cpp
    ManagerAuthenticationController.cpp
    ManagerMainWindow.cpp
    ManagerNetworkController.cpp
    main.cpp
)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_manager_gui
    PRIVATE
        Qt6::Charts
        Qt6::Core
        Qt6::Network
        Qt6::Widgets
        tesla_crypto
        tesla_core
        tesla_metrics
        tesla_protocol
        tesla_workload
)

set_target_properties(tesla_manager_gui
    PROPERTIES
        FOLDER "Applications"
        WIN32_EXECUTABLE TRUE
)
