add_executable(tesla_protocol_tests
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_protocol_tests PRIVATE tesla_core)

set_target_properties(tesla_protocol_tests
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Tests"
)

add_test(NAME tesla_protocol_tests COMMAND tesla_protocol_tests)
