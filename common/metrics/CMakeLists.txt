set(TESLA_METRICS_HEADERS
    include/tesla/metrics/AuthenticationMetrics.h
    include/tesla/metrics/CommunicationCost.h
    include/tesla/metrics/PerformanceCounterSampler.h
)

set(TESLA_METRICS_SOURCES
    src/AuthenticationMetrics.cpp
    src/CommunicationCost.cpp
    src/PerformanceCounterSampler.cpp
)

add_library(tesla_metrics STATIC
    ${TESLA_METRICS_HEADERS}
    ${TESLA_METRICS_SOURCES}
    CMakeLists.txt
)

source_group("Header Files" FILES ${TESLA_METRICS_HEADERS})
source_group("Source Files" FILES ${TESLA_METRICS_SOURCES})
source_group("Build Files" FILES CMakeLists.txt)

target_include_directories(tesla_metrics
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(tesla_metrics PUBLIC cxx_std_17)

set_target_properties(tesla_metrics
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Libraries"
)
