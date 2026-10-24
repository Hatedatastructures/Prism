/** @file Target.hpp @brief 协议私有 wire 地址到唯一正式网络目标的单次转换。 */
#pragma once
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Vless/Types.hpp>
namespace Prism::Vless::Detail
{
    /** @brief 借用解析后的 wire 地址；返回拥有目标或失败，无 I/O、取消和关闭副作用。 */
    [[nodiscard]] auto ToNetworkTarget(const Address& Input)
        -> std::expected<Prism::Network::Target, Prism::Fault::Failure>;
} // namespace Prism::Vless::Detail
