# 由 CheckPrismBoundaryEdges.mjs 调用：用表 2（_GetPrismAllowedInternalLinks）的真实判定校验单条边。
include("${BOUNDARY}")
_AssertPrismInternalLink("${C}" "${D}" "${D}" "INTERFACE_LINK_LIBRARIES")
message(STATUS "OK2 ${C} -> ${D}")
