add_library(ExperimentalNetRouteSupport INTERFACE)
target_sources(ExperimentalNetRouteSupport INTERFACE
    Outbound/Outbound.hpp
    Route/Route.hpp
)
add_subdirectory(Outbound)
add_subdirectory(Route)
