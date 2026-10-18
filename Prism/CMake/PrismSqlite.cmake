# 额度事务与本机历史使用同一固定 SQLite 源码依赖；业务 owner 仍采用 header-only。
include_guard(GLOBAL)
include(FetchContent)
FetchContent_Declare(PrismSqliteSource
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3540000.zip
    URL_HASH SHA3_256=7b670a62fdfbd672b75fef004cb703c8a3e87d3a5cc7d675b4a08337004a2d93
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(PrismSqliteSource)
add_library(PrismSqlite STATIC "${prismsqlitesource_SOURCE_DIR}/sqlite3.c")
target_include_directories(PrismSqlite PUBLIC "${prismsqlitesource_SOURCE_DIR}")
target_compile_definitions(PrismSqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION)
if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(PrismSqlite PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
endif()
