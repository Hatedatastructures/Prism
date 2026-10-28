# 由 CheckPrismBoundaryEdges.mjs 调用：对单条边执行 Prism 的真实边界策略。
# 用法：cmake -DBOUNDARY=<PrismBoundary.cmake> -DC=<consumer> -DD=<dependency> -P AssertPrismEdge.cmake
# 通过则输出 OK，违规由 AssertPrismDependency 自身 FATAL_ERROR，令退出码非零。
include("${BOUNDARY}")
AssertPrismDependency("${C}" "${D}")
message(STATUS "OK ${C} -> ${D}")
