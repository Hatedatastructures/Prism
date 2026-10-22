AddPrismTest(DirectoryLockTest.cpp)
target_link_libraries(DirectoryLockTest PRIVATE PrismApplication)
target_include_directories(DirectoryLockTest PRIVATE "${PROJECT_SOURCE_DIR}/Src")
