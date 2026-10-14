# 由 check_preview_boundary_edges.mjs 调用：对单条边执行 Preview 的真实边界策略。
# 用法：cmake -DBOUNDARY=<PreviewBoundary.cmake> -DC=<consumer> -DD=<dependency> -P AssertPreviewEdge.cmake
# 通过则输出 OK，违规由 AssertPreviewDependency 自身 FATAL_ERROR，令退出码非零。
include("${BOUNDARY}")
AssertPreviewDependency("${C}" "${D}")
message(STATUS "OK ${C} -> ${D}")
