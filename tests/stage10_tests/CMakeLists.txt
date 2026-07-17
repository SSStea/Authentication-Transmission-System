add_executable(tesla_stage10_tests
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_stage10_tests
    PRIVATE
        tesla_core
        tesla_crypto
        tesla_protocol
)

set_target_properties(tesla_stage10_tests
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Tests"
)

add_test(NAME tesla_stage10_tests COMMAND tesla_stage10_tests)
