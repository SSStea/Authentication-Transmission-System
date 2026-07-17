add_executable(tesla_stage7_tests
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_stage7_tests
    PRIVATE
        Threads::Threads
        tesla_core
        tesla_crypto
        tesla_protocol
        tesla_workload
)

set_target_properties(tesla_stage7_tests
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Tests"
)

add_test(NAME tesla_stage7_tests COMMAND tesla_stage7_tests)
