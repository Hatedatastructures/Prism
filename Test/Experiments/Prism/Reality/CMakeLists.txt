add_library(ExperimentalRealitySessionSupport INTERFACE)
target_sources(ExperimentalRealitySessionSupport INTERFACE
    Channel/SessionIdChannel.hpp
    Session/SessionIdSupport.hpp
    Session/SessionIdTool.hpp
    Session/SessionIdBenchSupport.hpp
)
add_subdirectory(Channel)
add_subdirectory(Session)
