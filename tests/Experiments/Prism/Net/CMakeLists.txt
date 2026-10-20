AddExperimentTest(RouteOutboundTest.cpp)
add_library(ExperimentalNetRouteSupport INTERFACE)
target_sources(ExperimentalNetRouteSupport INTERFACE
    Outbound/Outbound.hpp
    Route/Route.hpp
)
target_link_libraries(ExperimentRouteOutboundTest PRIVATE ExperimentalNetRouteSupport)
target_link_libraries(ExperimentRouteOutboundTest PRIVATE PrismNet)
