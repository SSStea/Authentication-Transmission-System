add_executable(tesla_stage6_tests
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_stage6_tests
    PRIVATE
        Threads::Threads
        tesla_core
        tesla_crypto
        tesla_protocol
        tesla_workload
)

set_target_properties(tesla_stage6_tests
    PROPERTIES
        FOLDER "Tests"
)

add_test(NAME tesla_stage6_tests COMMAND tesla_stage6_tests)
