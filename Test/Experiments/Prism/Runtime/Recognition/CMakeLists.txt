add_library(ExperimentalProbeDefenseSupport INTERFACE)
target_sources(ExperimentalProbeDefenseSupport INTERFACE Probe/ProbeDefense.hpp)

add_library(ExperimentalRecognitionSupport INTERFACE)
target_sources(ExperimentalRecognitionSupport INTERFACE
    Probe/ProbeRecognition.hpp
    Route/Route.hpp
    Scheme/SchemeExecutor.hpp
    Pipeline/RecognitionSupport.hpp
    Tls/TlsRecognitionSupport.hpp
)
add_subdirectory(Pipeline)
add_subdirectory(Probe)
add_subdirectory(Route)
add_subdirectory(Scheme)
add_subdirectory(Tls)
