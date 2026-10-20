AddExperimentTest(ProbeDefenseCoverage.cpp)
add_library(ExperimentalProbeDefenseSupport INTERFACE)
target_sources(ExperimentalProbeDefenseSupport INTERFACE ProbeDefense.hpp)
target_link_libraries(ExperimentProbeDefenseCoverage PRIVATE ExperimentalProbeDefenseSupport)
target_link_libraries(ExperimentProbeDefenseCoverage PRIVATE PrismRuntime)

AddExperimentTest(RecognitionRouteTest.cpp)
AddExperimentTest(RecognitionPipelineTest.cpp)
AddExperimentTest(SchemeExecutorTest.cpp)
AddExperimentTest(TlsRouteTableTest.cpp)
AddExperimentTest(TlsExperimentPipelineTest.cpp)

add_library(ExperimentalRecognitionSupport INTERFACE)
target_sources(ExperimentalRecognitionSupport INTERFACE
    ../../ProbeRecognition.hpp
    ../../Route.hpp
    ../../SchemeExecutor.hpp
    RecognitionExperimentTestSupport.hpp
    TlsRecognitionExperimentTestSupport.hpp
)
target_link_libraries(ExperimentRecognitionRouteTest PRIVATE
    ExperimentalRecognitionSupport PrismFoundation PrismTransport PrismRuntime)
target_include_directories(ExperimentRecognitionRouteTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(ExperimentRecognitionPipelineTest PRIVATE
    ExperimentalRecognitionSupport PrismFoundation PrismTransport PrismRuntime)
target_include_directories(ExperimentRecognitionPipelineTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(ExperimentSchemeExecutorTest PRIVATE
    ExperimentalRecognitionSupport PrismTransport PrismRuntime)
target_include_directories(ExperimentSchemeExecutorTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(ExperimentTlsRouteTableTest PRIVATE
    ExperimentalRecognitionSupport PrismFoundation PrismTransport PrismRuntime)
target_include_directories(ExperimentTlsRouteTableTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
target_link_libraries(ExperimentTlsExperimentPipelineTest PRIVATE PrismFoundation PrismTransport PrismRuntime)
target_link_libraries(ExperimentTlsExperimentPipelineTest PRIVATE ExperimentalRecognitionSupport)
target_include_directories(ExperimentTlsExperimentPipelineTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
