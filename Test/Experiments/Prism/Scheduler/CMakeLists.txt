add_library(ExperimentalSchedulerSupport INTERFACE)
target_sources(ExperimentalSchedulerSupport INTERFACE
    Core/Types.hpp
    Core/Scheduler.hpp
    Detail/FixedTable.hpp
    Policy/FairScheduler.hpp
    Policy/PriorityScheduler.hpp
)
add_subdirectory(Core)
