/**
 * @file types.hpp
 * @brief 协议类型枚举（兼容重导出）
 * @details protocol_type 已下沉到 net/connect/types.hpp。
 *          本文件保留为 using 声明，确保旧代码平滑过渡。
 */
#pragma once

#include <prism/net/connect/types.hpp>

namespace psm::protocol
{

using psm::connect::protocol_type;
using psm::connect::to_string_view;

} // namespace psm::protocol
