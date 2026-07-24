/**
 * @file target.hpp
 * @brief 目标地址信息（兼容重导出）
 * @details target 已下沉到 net/connect/target.hpp。
 *          本文件保留为 using 声明，确保旧代码平滑过渡。
 */
#pragma once

#include <prism/net/connect/target.hpp>

namespace psm::protocol
{

using psm::connect::target;

} // namespace psm::protocol
