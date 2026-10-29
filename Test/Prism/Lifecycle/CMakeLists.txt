AddPrismTest(Task/RegistryTest.cpp TaskRegistryTest)
AddPrismTest(Task/IdSetTest.cpp TaskIdSetTest)
target_link_libraries(TaskIdSetTest PRIVATE PrismLifecycle)
target_link_libraries(TaskRegistryTest PRIVATE PrismLifecycle PrismTestSupport)
AddPrismTest(Task/RegistryAuditTest.cpp TaskRegistryAuditTest)
target_link_libraries(TaskRegistryAuditTest PRIVATE PrismLifecycle PrismTestSupport)
target_sources(TaskRegistryAuditTest PRIVATE Task/HandleTestAccess.hpp)
AddPrismTest(Task/RegistryCoreTest.cpp TaskRegistryCoreTest)
AddPrismTest(Task/RegistryDrainTest.cpp TaskRegistryDrainTest)
AddPrismTest(Task/OwnershipTest.cpp TaskOwnershipLifecycleTest)
target_link_libraries(TaskRegistryCoreTest PRIVATE PrismFoundation PrismLifecycle PrismRuntime)
target_sources(TaskRegistryCoreTest PRIVATE Task/LifecycleTestSupport.hpp)
target_link_libraries(TaskRegistryDrainTest PRIVATE PrismFoundation PrismLifecycle PrismRuntime)
target_sources(TaskRegistryDrainTest PRIVATE Task/LifecycleTestSupport.hpp)
target_link_libraries(TaskOwnershipLifecycleTest PRIVATE PrismFoundation PrismLifecycle PrismRuntime)
target_sources(TaskOwnershipLifecycleTest PRIVATE Task/LifecycleTestSupport.hpp)


# 同一实际owner的源文件，复用现有target。
target_sources(TaskRegistryCoreTest PRIVATE
    Task/HandleTestAccess.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(TaskRegistryDrainTest PRIVATE
    Task/HandleTestAccess.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(TaskOwnershipLifecycleTest PRIVATE
    Task/HandleTestAccess.hpp
)
