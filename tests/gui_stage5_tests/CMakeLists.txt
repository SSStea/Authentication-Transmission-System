add_executable(tesla_gui_stage5_tests
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_gui_stage5_tests
    PRIVATE
        Qt6::Core
)

set_target_properties(tesla_gui_stage5_tests
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Tests"
)

add_dependencies(tesla_gui_stage5_tests
    tesla_manager_gui
    tesla_pc_node_gui
    tesla_uav_monitor_gui
    tesla_attack_test_gui
)

add_test(
    NAME tesla_gui_stage5_tests
    COMMAND tesla_gui_stage5_tests
        --manager $<TARGET_FILE:tesla_manager_gui>
        --pc-node $<TARGET_FILE:tesla_pc_node_gui>
        --uav-monitor $<TARGET_FILE:tesla_uav_monitor_gui>
        --attack-test $<TARGET_FILE:tesla_attack_test_gui>
)

get_filename_component(TESLA_QT_BIN_DIR "${Qt6_DIR}/../../../bin" ABSOLUTE)
set_tests_properties(tesla_gui_stage5_tests
    PROPERTIES
        TIMEOUT 45
        RUN_SERIAL TRUE
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${TESLA_QT_BIN_DIR}"
)
