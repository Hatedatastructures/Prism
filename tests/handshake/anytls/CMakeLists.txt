AddProductionTest(AnytlsFrameParse.cpp)
AddProductionTest(AnytlsPadding.cpp)
AddProductionTest(AnytlsPaddingPure.cpp)
AddProductionTest(AnytlsScheme.cpp)
AddProductionTest(AnytlsSchemeDeep.cpp)
AddProductionTest(AnytlsSchemeDeep2.cpp)
AddProductionTest(AnytlsSchemeExtended.cpp)

AddProductionTest(AnytlsSessionDeep.cpp)

AddProductionTest(AnytlsSessionDispatchTest.cpp)

AddProductionTest(AnytlsSessionFrameLifecycleTest.cpp)

foreach(AnytlsTarget IN ITEMS
        AnytlsSessionDeep
        AnytlsSessionDispatchTest
        AnytlsSessionFrameLifecycleTest)
    target_sources(${AnytlsTarget} PRIVATE AnytlsSessionDeepSupport.hpp)
endforeach()
