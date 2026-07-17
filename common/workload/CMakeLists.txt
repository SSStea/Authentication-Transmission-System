set(TESLA_WORKLOAD_HEADERS
    include/tesla/workload/TextWorkload.h
)

set(TESLA_WORKLOAD_SOURCES
    src/TextWorkload.cpp
)

add_library(tesla_workload STATIC
    ${TESLA_WORKLOAD_HEADERS}
    ${TESLA_WORKLOAD_SOURCES}
    CMakeLists.txt
)

source_group("Header Files" FILES ${TESLA_WORKLOAD_HEADERS})
source_group("Source Files" FILES ${TESLA_WORKLOAD_SOURCES})
source_group("Build Files" FILES CMakeLists.txt)

target_include_directories(tesla_workload
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(tesla_workload PUBLIC cxx_std_17)
target_link_libraries(tesla_workload PUBLIC tesla_crypto)

set_target_properties(tesla_workload
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Libraries"
)
