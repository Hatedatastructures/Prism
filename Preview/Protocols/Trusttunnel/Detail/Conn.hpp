/**
 * @file Conn.hpp
 * @brief TrustTunnel 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 TrustTunnel 连接（对齐 mihomo
 * transport/trusttunnel/Client.go）：
 * 1. WriteHandshake：发送 HTTP/2 CONNECT 请求头（含 Basic Auth）
 * 2. ReadHandshake：服务端解析 CONNECT 请求并校验认证
 * 3. 数据面：HTTP/2 数据帧承载（测试库简化透传）
 * @note 与 trusttunnel.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/ForwardedActivity.hpp>
#include <Preview/Protocols/Trusttunnel/Codec.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>
#include <Preview/Protocols/Trusttunnel/Conn.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <expected>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Trusttunnel::Detail
{
/**
     * @class Conn
     * @brief TrustTunnel 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory>
    class Conn : public Preview::Transmission
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /** @brief 校验上游并创建流连接；空上游在冷路径正式拒绝。 */
        [[nodiscard]] static auto Create(ConnRequest Request)
            -> std::expected<std::shared_ptr<Conn>, Preview::Fault::Failure>
        {
            if (!Request.Upstream)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            return std::shared_ptr<Conn>(new Conn(std::move(Request)));
        }

    private:
        /**
         * @brief 从已校验的冷路径输入构造连接
         */
        explicit Conn(ConnRequest Request)
            : Preview::Transmission(Request.Upstream->Executor()),
              NextLayer_(std::move(Request.Upstream)), User_(std::move(Request.User)),
              Pass_(std::move(Request.Password))
        {
            Activity_ = std::make_shared<ForwardedActivity>(
                Preview::Transmission::Activity(), NextLayer_->Activity(), CloseReceipt());
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
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        /** @brief 客户端握手：写出 Basic CONNECT 并保留底层 typed failure。 */
        [[nodiscard]] auto WriteHandshake(
            std::string_view Target,
            std::uint16_t Port)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Handshaken_ = false;
            Activity_->Seal();
            if (!NextLayer_)
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            const auto Auth = BasicAuth(User_, Pass_);
            std::string Header;
            Header.reserve(64 + Target.size() + Auth.size());
            Header += "CONNECT " + std::string(Target) + ":" + std::to_string(Port) + " HTTP/2\r\n";
            Header += "Proxy-Authorization: " + Auth + "\r\n\r\n";
            const auto Sent = co_await SendBytes(AsU8Span(Header));
            if (!Sent) co_return std::unexpected(Sent.error());
            Target_ = std::string(Target);
            Handshaken_ = true;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 服务端握手：解析 CONNECT 并分别保留认证、EOF 与原生 I/O 失败。 */
        [[nodiscard]] auto ReadHandshake(std::string &Target)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Handshaken_ = false;
            Target.clear();
            if (!NextLayer_)
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            std::array<std::uint8_t, 256> Chunk{};
            std::string Header;
            Preview::Fault::Failure ReadFailure;
            for (int Index = 0; Index < 16; ++Index)
            {
                const auto Part = co_await NextLayer_->ReadSome(AsBytes(std::span<std::uint8_t>(Chunk)));
                if (Part.Bytes > Chunk.size())
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                if (Part.Bytes != 0)
                    Header.append(reinterpret_cast<const char *>(Chunk.data()), Part.Bytes);
                if (Header.find("\r\n\r\n") != std::string::npos) break;
                if (Part.Failure.Failed())
                {
                    ReadFailure = Part.Failure;
                    break;
                }
                if (Part.Bytes == 0)
                {
                    ReadFailure = {Preview::Fault::Code::Eof};
                    break;
                }
            }
            const auto HeaderEnd = Header.find("\r\n\r\n");
            if (HeaderEnd == std::string::npos)
            {
                if (ReadFailure.Failed()) co_return std::unexpected(ReadFailure);
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
            }
            const auto FirstLineEnd = Header.find("\r\n");
            if (FirstLineEnd == std::string::npos || FirstLineEnd > HeaderEnd ||
                Header.find("CONNECT ") != 0)
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
            const auto TargetLine = Header.substr(8, FirstLineEnd - 8);
            const auto Colon = TargetLine.find(':');
            Target = TargetLine;
            if (Colon != std::string::npos)
            {
                Target = TargetLine.substr(0, Colon);
            }
            const auto Auth = HeaderValue(Header, "Proxy-Authorization");
            if (!Auth || !VerifyBasicAuth(*Auth, User_, Pass_))
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::AuthFailed});
            Target_ = Target;
            PreserveHandshakeTail(Header, HeaderEnd + 4);
            Handshaken_ = true;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /**
         * @brief 预读缓冲优先的部分读取
         * @details 命中握手超读缓冲、缓冲区为空或底层不可用时，结果异步交付一次；
         *          否则 token 直通底层，保留底层短读与 EOF 事实。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            if (Buffer.empty() || PendingOffset_ < PendingWire_.size())
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), TakePending(Buffer));
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 透传写入（数据面原样）
         * @details 未握手或底层已释放时异步交付一次 NotOpen；否则 token 直通底层。
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
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
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 清除握手状态并交付底层关闭
         * @return 命令接管成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Handshaken_ = false;
            Activity_->Seal();
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Close();
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
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            Handshaken_ = false;
            Activity_->ReleaseChild();
            return std::move(NextLayer_);
        }

    private:
        /** @brief 写完握手载荷并返回首个底层 typed failure。 */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (!NextLayer_)
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                const auto Part = co_await NextLayer_->WriteSome(AsBytes(Data.subspan(Offset)));
                if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
                const auto Remaining = Data.size() - Offset;
                if (Part.Bytes == 0)
                    co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::WouldBlock});
                if (Part.Bytes > Remaining)
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                Offset += Part.Bytes;
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 消费握手超读缓冲；空缓冲或已消费完返回 0 字节成功。 */
        [[nodiscard]] auto TakePending(std::span<std::byte> Buffer) -> Preview::IoResult
        {
            if (Buffer.empty() || PendingOffset_ >= PendingWire_.size())
            {
                return {0, {}};
            }
            const auto Count = (std::min)(Buffer.size(), PendingWire_.size() - PendingOffset_);
            std::memcpy(Buffer.data(), PendingWire_.data() + PendingOffset_, Count);
            PendingOffset_ += Count;
            if (PendingOffset_ == PendingWire_.size())
            {
                PendingWire_.clear();
                PendingOffset_ = 0;
            }
            return {Count, {}};
        }

        auto PreserveHandshakeTail(const std::string &Data, std::size_t Offset) -> void
        {
            PendingWire_.clear();
            PendingOffset_ = 0;
            if (Offset < Data.size())
            {
                const auto *Begin = reinterpret_cast<const std::byte *>(Data.data() + Offset);
                PendingWire_.assign(Begin, Begin + (Data.size() - Offset));
            }
        }

        SharedTransmission NextLayer_;
        std::shared_ptr<ForwardedActivity> Activity_;  ///< 底层传输（独占所有权）
        std::string User_;                ///< 认证用户名
        std::string Pass_;                ///< 认证密码
        std::string Target_;              ///< CONNECT 目标（握手后）
        bool Handshaken_{false};          ///< 握手完成标志
        std::vector<std::byte> PendingWire_; ///< 握手读取时回注的后续数据
        std::size_t PendingOffset_{0};       ///< 回注数据消费位置
    };

    /// 流连接共享指针（默认内存策略）
static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Trusttunnel::Detail
