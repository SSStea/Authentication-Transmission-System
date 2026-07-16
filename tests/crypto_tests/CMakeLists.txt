add_executable(tesla_crypto_tests
    main.cpp
    CMakeLists.txt
)

source_group("Source Files" FILES main.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_link_libraries(tesla_crypto_tests PRIVATE tesla_crypto)

set_target_properties(tesla_crypto_tests
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Tests"
)

add_test(NAME tesla_crypto_tests COMMAND tesla_crypto_tests)
