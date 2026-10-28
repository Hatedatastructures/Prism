# Web资源与当前Main使用同一build树，但不属于默认C++生产target。
find_program(PrismNodeExecutable NAMES node)
find_program(PrismNpmExecutable NAMES npm.cmd npm)
if(NOT PrismNodeExecutable)
    set(PrismNodeExecutable node)
endif()
if(NOT PrismNpmExecutable)
    if(WIN32)
        set(PrismNpmExecutable npm.cmd)
    else()
        set(PrismNpmExecutable npm)
    endif()
endif()

add_custom_command(
    OUTPUT "${CMAKE_BINARY_DIR}/Web/catalog.json"
    COMMAND "${PrismNpmExecutable}" --prefix "${PROJECT_SOURCE_DIR}/Web" run build -- --outDir "${CMAKE_BINARY_DIR}/Web"
    COMMAND "${PrismNodeExecutable}" "${PROJECT_SOURCE_DIR}/Scripts/BuildPrismWebCatalog.mjs" "${CMAKE_BINARY_DIR}/Web" "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    DEPENDS
        "${PROJECT_SOURCE_DIR}/Web/index.html"
        "${PROJECT_SOURCE_DIR}/Web/package-lock.json"
        "${PROJECT_SOURCE_DIR}/Web/package.json"
        "${PROJECT_SOURCE_DIR}/Web/public/PrismMark.svg"
        "${PROJECT_SOURCE_DIR}/Web/src/Api/ConfigurationDocument.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Api/JsonDocument.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/App/AdminServices.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/App/App.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/App/AppShell.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Components/ConfirmAction.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Components/Ui.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Accounts/AccountsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Configuration/ConfigurationPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Events/EventsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Ingresses/IngressesPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Operations/OperationsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Overview/OverviewPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Sessions/SessionsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/UserGroups/UserGroupsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/UseOperations.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Workers/WorkersPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Main.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Services/AdminDataSource.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Services/DemoAdminDataSource.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Styles/Theme.css"
        "${PROJECT_SOURCE_DIR}/Web/README.md"
        "${PROJECT_SOURCE_DIR}/Web/tsconfig.json"
        "${PROJECT_SOURCE_DIR}/Web/vite.config.ts"
        "${PROJECT_SOURCE_DIR}/Scripts/BuildPrismWebCatalog.mjs"
    VERBATIM
)
add_custom_target(PrismWeb DEPENDS "${CMAKE_BINARY_DIR}/Web/catalog.json")
