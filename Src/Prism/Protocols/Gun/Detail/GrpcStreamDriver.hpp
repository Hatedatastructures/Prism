/**
 * @file GrpcStreamDriver.hpp
 * @brief gRPC stream HTTP/2 读写驱动的启动与完成所有者。
 * @details 每个 driver 在投递前登记，在协程真实退栈后归还活动计数。
 */
#pragma once

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamOwner.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>

#include <exception>
#include <cstddef>
#include <memory>
#include <span>
#include <utility>

namespace Prism::Gun::Grpc::Detail
{
    /** @brief gRPC carrier 一次底层 HTTP/2 读取窗口及其 typed completion。 */
    struct GrpcReadCompletion final
    {
        std::span<const std::byte> Buffer;
        Prism::IoResult Result{};
    };

    /**
     * @brief 一次 gRPC HTTP/2 输入步骤的继续/终态与关联失败。
     * @details LowerTerminal 仅表示成功 Feed 字节后由下层同读返回的原始终态。
     */
    struct GrpcReadStep final
    {
        bool Terminal{false};
        Prism::Fault::Failure Failure{};
        bool LowerTerminal{false};
    };

    /** @brief 先向 HTTP/2 session 喂入已交付字节，再决定该 completion 是否终止驱动。 */
    [[nodiscard]] auto ProcessGrpcReadCompletion(
        Prism::Http2::Session &Session,
        const GrpcReadCompletion &Completion) -> GrpcReadStep;

    /**
     * @class GrpcStreamDriver
     * @brief 唯一持有并启动 gRPC stream 的双向帧驱动。
     */
    struct GrpcStreamDriver final
    {
        /** @brief 启动唯一读驱动，并登记其真实协程寿命。 */
        static auto StartRead(const std::shared_ptr<StreamTransport> &Owner) -> void;

        /** @brief 启动唯一写驱动，并登记其真实协程寿命。 */
        static auto StartWrite(const std::shared_ptr<StreamTransport> &Owner) -> void;

    private:
        static auto Complete(
            const std::shared_ptr<StreamTransport> &Owner,
            std::exception_ptr Exception) noexcept -> void;
    };
} // namespace Prism::Gun::Grpc::Detail
