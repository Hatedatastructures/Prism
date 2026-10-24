AddPrismTest(Task/TaskRegistryTest.cpp)
AddPrismTest(Task/TaskIdSetTest.cpp)
target_link_libraries(TaskIdSetTest PRIVATE PrismLifecycle)
target_link_libraries(TaskRegistryTest PRIVATE PrismLifecycle PrismTestSupport)
AddPrismTest(Task/TaskRegistryAuditTest.cpp)
target_link_libraries(TaskRegistryAuditTest PRIVATE PrismLifecycle PrismTestSupport)
target_sources(TaskRegistryAuditTest PRIVATE Task/TaskHandleTestAccess.hpp)
AddPrismTest(Task/TaskRegistryCoreTest.cpp)
AddPrismTest(Task/TaskRegistryDrainTest.cpp)
AddPrismTest(Task/TaskOwnershipLifecycleTest.cpp)
target_link_libraries(TaskRegistryCoreTest PRIVATE PrismFoundation PrismLifecycle PrismRuntime)
target_sources(TaskRegistryCoreTest PRIVATE Task/TaskLifecycleTestSupport.hpp)
target_link_libraries(TaskRegistryDrainTest PRIVATE PrismFoundation PrismLifecycle PrismRuntime)
target_sources(TaskRegistryDrainTest PRIVATE Task/TaskLifecycleTestSupport.hpp)
target_link_libraries(TaskOwnershipLifecycleTest PRIVATE PrismFoundation PrismLifecycle PrismRuntime)
target_sources(TaskOwnershipLifecycleTest PRIVATE Task/TaskLifecycleTestSupport.hpp)


# 同一实际owner的源文件，复用现有target。
target_sources(TaskRegistryCoreTest PRIVATE
    Task/TaskHandleTestAccess.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(TaskRegistryDrainTest PRIVATE
    Task/TaskHandleTestAccess.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(TaskOwnershipLifecycleTest PRIVATE
    Task/TaskHandleTestAccess.hpp
)
