/**
 * @file GrpcStreamFactory.hpp
 * @brief gRPC stream accept 工厂与握手失败退休 owner。
 * @details I/O 前预约输入和 stream owner；只有 request headers 握手成功后才释放票据。
 */
#pragma once

#include <Prism/Protocols/Gun/Detail/GrpcStreamOwner.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamDriver.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/redirect_error.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Gun::Grpc::Detail
{
    /**
     * @class StreamFactory
     * @brief 唯一创建 gRPC stream transport 的正式工厂。
     */
    class StreamFactory final
    {
    public:
        /**
         * @brief 接收 gRPC HTTP/2 stream 并完成首个 request headers 握手。
         * @param Lower 按值接管的下层加密传输；执行域固定为其 executor。
         * @param ConfigValue 按值持有的 path 与 message 限额。
         * @return 拥有型 stream 或保留 Native 的首个 typed Failure。
         * @details I/O 前预建失败退休 ticket；失败执行 Cancel、Close、driver 与 activity
         *          drain，成功后 ticket 转交给 stream。写半关闭只结束本地 trailers；最终
         *          Close 由 stream owner 转交下层，driver completion 等待真实协程退栈。
         */
        [[nodiscard]] static auto Accept(
            Prism::SharedTransmission Lower,
            Config ConfigValue)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>;
    };
} // namespace Prism::Gun::Grpc::Detail
