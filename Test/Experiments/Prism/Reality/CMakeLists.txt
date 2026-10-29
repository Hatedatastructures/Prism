add_library(ExperimentalRealitySessionSupport INTERFACE)
target_sources(ExperimentalRealitySessionSupport INTERFACE
    Channel/SessionIdChannel.hpp
    Session/IdSupport.hpp
    Session/IdTool.hpp
    Session/IdBenchSupport.hpp
)
add_subdirectory(Channel)
add_subdirectory(Session)
