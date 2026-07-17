qt_add_executable(tesla_attack_test_gui
    AttackExecutionController.cpp
    AttackExecutionController.h
    AttackTestMainWindow.cpp
    AttackTestMainWindow.h
    AttackTestNetworkController.cpp
    AttackTestNetworkController.h
    main.cpp
    CMakeLists.txt
)

source_group("Header Files" FILES
    AttackExecutionController.h
    AttackTestMainWindow.h
    AttackTestNetworkController.h
)
source_group("Source Files" FILES
    AttackTestMainWindow.cpp
    AttackExecutionController.cpp
    AttackTestNetworkController.cpp
    main.cpp
)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_attack_test_gui
    PRIVATE
        Qt6::Charts
        Qt6::Core
        Qt6::Network
        Qt6::Widgets
        tesla_metrics
        tesla_protocol
)

set_target_properties(tesla_attack_test_gui
    PROPERTIES
        FOLDER "Applications"
        WIN32_EXECUTABLE TRUE
)
