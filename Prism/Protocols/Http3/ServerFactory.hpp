/** @file ServerFactory.hpp @brief 实际 HTTP3 frame session 创建能力，Hysteria2 独立校验并消费。 */
#pragma once
#include <Prism/Protocols/Http3/Server.hpp>
namespace Prism::Http3
{
    class ServerFactory final
    {
    public:
        /** @brief 接管纯配置创建 owning HTTP3 frame session，不拥有 QUIC socket 或连接关闭权。 */
        [[nodiscard]] auto Create(ServerOptions Options) const -> SharedServer
        { return std::make_shared<Server>(Options); }
    };
}
