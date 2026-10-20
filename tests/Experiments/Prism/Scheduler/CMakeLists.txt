AddExperimentTest(SchedulerTest.cpp)
add_library(ExperimentalSchedulerSupport INTERFACE)
target_sources(ExperimentalSchedulerSupport INTERFACE
    Types.hpp
    Detail/FixedTable.hpp
    FairScheduler.hpp
    PriorityScheduler.hpp
    Scheduler.hpp
)
target_link_libraries(ExperimentSchedulerTest PRIVATE ExperimentalSchedulerSupport)
target_link_libraries(ExperimentSchedulerTest PRIVATE PrismFoundation)
