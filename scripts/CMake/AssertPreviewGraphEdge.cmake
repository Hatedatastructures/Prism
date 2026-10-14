# 由 check_preview_boundary_edges.mjs 调用：用表 2（_GetPreviewAllowedInternalLinks）的真实判定校验单条边。
include("${BOUNDARY}")
_AssertPreviewInternalLink("${C}" "${D}" "${D}" "INTERFACE_LINK_LIBRARIES")
message(STATUS "OK2 ${C} -> ${D}")
