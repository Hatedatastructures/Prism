/**
 * @file Dgram.hpp
 * @brief TrustTunnel UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层传输包装为 HTTP/2 数据帧承载的
 * 包连接（对齐 mihomo transport/trusttunnel ListenPacket）。
 * 帧格式：[DATA 帧头 9B][负载]（简化：测试库直接透传数据报，
 * 帧编解码由上层 HTTP/2 层负责）。
 * @note 继承 Prism::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/ForwardedActivity.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Protocols/Trusttunnel/Dgram.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <expected>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Trusttunnel::Detail
{
/**
     * @class Dgram
     * @brief TrustTunnel UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom）。
     */
    class Dgram : public Prism::Transmission
    {
    public:
        /** @brief 校验上游并创建包连接；空上游返回 typed failure。 */
        [[nodiscard]] static auto Create(DgramRequest Request)
            -> std::expected<std::shared_ptr<Dgram>, Prism::Fault::Failure>
        {
            if (!Request.Upstream)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            return std::shared_ptr<Dgram>(new Dgram(std::move(Request)));
        }

    private:
        /**
         * @brief 从已校验的冷路径输入构造包连接
         */
        explicit Dgram(DgramRequest Request)
            : Prism::Transmission(Request.Upstream->Executor()),
              NextLayer_(std::move(Request.Upstream))
        {
            Activity_ = std::make_shared<ForwardedActivity>(
                Prism::Transmission::Activity(), NextLayer_->Activity(), CloseReceipt());
        }

    public:
        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        /**
         * @brief 传输类型（TCP 承载数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param Host 目标主机
         * @param Port 目标端口
         * @param Payload 载荷
         * @return expected 成功值或保留 Code/Native 的 typed 失败。
         */
        [[nodiscard]] auto AsyncSendTo(
            std::string_view Host,
            std::uint16_t Port,
            std::span<const std::uint8_t> Payload)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (Host.size() > std::numeric_limits<std::uint8_t>::max())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            // 简化：UDP 数据报带 1 字节长度 + 主机 + 2 字节端口 + 载荷透传
            std::vector<std::uint8_t> Wire;
            Wire.reserve(1 + Host.size() + 2 + Payload.size());
            Wire.push_back(static_cast<std::uint8_t>(Host.size()));
            Wire.insert(Wire.end(), Host.begin(), Host.end());
            Wire.push_back(static_cast<std::uint8_t>(Port >> 8));
            Wire.push_back(static_cast<std::uint8_t>(Port & 0xFF));
            Wire.insert(Wire.end(), Payload.begin(), Payload.end());
            std::size_t Done = 0;
            while (Done < Wire.size())
            {
                const auto Part = co_await NextLayer_->WriteSome(
                    AsBytes(std::span<const std::uint8_t>(Wire)).subspan(Done));
                const auto N = Part.Bytes;
                if (N > Wire.size() - Done)
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                Done += N;
                if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
                if (N == 0)
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param Host 输出源主机
         * @param Port 输出源端口
         * @param Payload 输出载荷
         * @return expected 成功值或保留部分读取与 Code/Native 的 typed 失败。
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            std::string &Host,
            std::uint16_t &Port,
            std::vector<std::uint8_t> &Payload)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            Host.clear();
            Port = 0;
            Payload.clear();
            std::array<std::uint8_t, 1> HostLength{};
            auto Read = co_await ReadExact(HostLength);
            if (!Read) co_return std::unexpected(Read.error());
            std::vector<std::uint8_t> HostBuf(HostLength[0]);
            Read = co_await ReadExact(HostBuf);
            if (!Read) co_return std::unexpected(Read.error());
            Host.assign(reinterpret_cast<const char *>(HostBuf.data()), HostBuf.size());
            std::array<std::uint8_t, 2> PortBuf{};
            Read = co_await ReadExact(PortBuf);
            if (!Read) co_return std::unexpected(Read.error());
            Port = static_cast<std::uint16_t>(PortBuf[0]) << 8 | PortBuf[1];
            std::array<std::uint8_t, 512> Chunk{};
            const auto Part = co_await NextLayer_->ReadSome(
                AsBytes(std::span<std::uint8_t>(Chunk)));
            const auto N = Part.Bytes;
            if (N > Chunk.size())
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            Payload.assign(Chunk.begin(), Chunk.begin() + static_cast<std::ptrdiff_t>(N));
            if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
            if (N == 0)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Eof});
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /**
         * @brief 透传读取（底层原样）
         * @details 底层缺失时异步交付一次 NotOpen；否则 token 直通底层。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 透传写入（底层原样）
         * @details 底层缺失时异步交付一次 NotOpen；否则 token 直通底层。
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 真实写半关闭转交底层载体；反向读取仍然可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 封止并交付底层关闭
         * @return 命令接管成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto Result = NextLayer_ ? NextLayer_->Close() : ControlResult{};
            Activity_->Seal();
            return Result;
        }

        /**
         * @brief 可重复取消底层挂起操作
         * @return 命令接管成功只表示取消请求已排入原 executor，不宣称已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            Activity_->ReleaseChild();
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取底层传输
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto Part = co_await NextLayer_->ReadSome(
                    AsBytes(Buffer.subspan(Done)));
                if (Part.Bytes > Buffer.size() - Done)
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                Done += Part.Bytes;
                if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
                if (Part.Bytes == 0)
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Eof});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        SharedTransmission NextLayer_;
        std::shared_ptr<ForwardedActivity> Activity_; ///< 底层传输（独占所有权）
    };

    /// 包连接共享指针
static_assert(Prism::TransmissionLike<Dgram>);

} // namespace Prism::Trusttunnel::Detail
