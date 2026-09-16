/**
 * @file Gun.hpp
 * @brief gRPC (gun) 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——CONNECT 握手在工厂内部完成
 * - 连接：Conn（流，Conn.hpp，CONNECT 握手 + 数据透传）
 * - 编解码：Codec.hpp（protobuf varint + gun 帧编解码）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Gun/Codec.hpp>
#include <Preview/Protocols/Gun/Conn.hpp>
#include <Preview/Protocols/Gun/Types.hpp>

namespace Preview::Gun
{

    /**
     * @brief 创建客户端流连接并完成 CONNECT 握手
     * @param Upstream 上游传输（所有权移交）
     * @param Host 目标主机
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        std::string_view Host) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream));
        const auto ErrorCode = co_await Connection->WriteHandshake(Host);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Connection->Close();
        }
        co_return std::pair{ErrorCode, std::move(Result)};
    }

    /**
     * @brief 接收服务端流连接并完成 CONNECT 握手
     * @param Upstream 上游传输（所有权移交）
     * @return 错误码、解析的目标与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission Upstream)
        -> Net::awaitable<std::tuple<Error, std::string, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream));
        std::string Host;
        const auto ErrorCode = co_await Connection->ReadHandshake(Host);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Connection->Close();
        }
        co_return std::tuple{ErrorCode, std::move(Host), std::move(Result)};
    }

} // namespace Preview::Gun
