add_library(ExperimentalProbeDefenseSupport INTERFACE)
target_sources(ExperimentalProbeDefenseSupport INTERFACE Probe/Defense.hpp)

add_library(ExperimentalRecognitionSupport INTERFACE)
target_sources(ExperimentalRecognitionSupport INTERFACE
    Probe/Recognition.hpp
    Route/Route.hpp
    Scheme/Executor.hpp
    Pipeline/RecognitionSupport.hpp
    Tls/RecognitionSupport.hpp
)
add_subdirectory(Pipeline)
add_subdirectory(Probe)
add_subdirectory(Route)
add_subdirectory(Scheme)
add_subdirectory(Tls)
