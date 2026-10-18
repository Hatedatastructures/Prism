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

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/ForwardedActivity.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Protocols/Trusttunnel/Conn.hpp>

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

namespace Prism::Trusttunnel::Detail
{
/**
     * @class Conn
     * @brief TrustTunnel 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Prism::Memory::Restrict Memory>
    class Conn : public Prism::Transmission
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /** @brief 校验上游并创建流连接；空上游在冷路径正式拒绝。 */
        [[nodiscard]] static auto Create(ConnRequest Request)
            -> std::expected<std::shared_ptr<Conn>, Prism::Fault::Failure>
        {
            if (!Request.Upstream)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            return std::shared_ptr<Conn>(new Conn(std::move(Request)));
        }

    private:
        /**
         * @brief 从已校验的冷路径输入构造连接
         */
        explicit Conn(ConnRequest Request)
            : Prism::Transmission(Request.Upstream->Executor()),
              NextLayer_(std::move(Request.Upstream)), User_(std::move(Request.User)),
              Pass_(std::move(Request.Password))
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

        /** @brief 客户端握手：写出 Basic CONNECT 并保留底层 typed failure。 */
        [[nodiscard]] auto WriteHandshake(
            std::string_view Target,
            std::uint16_t Port)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Handshaken_ = false;
            if (!NextLayer_)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            const auto Auth = BasicAuth(User_, Pass_);
            std::string Header;
            Header.reserve(64 + Target.size() + Auth.size());
            Header += "CONNECT " + std::string(Target) + ":" + std::to_string(Port) + " HTTP/2\r\n";
            Header += "Proxy-Authorization: " + Auth + "\r\n\r\n";
            const auto Sent = co_await SendBytes(AsU8Span(Header));
            if (!Sent) co_return std::unexpected(Sent.error());
            Target_ = std::string(Target);
            Handshaken_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 服务端握手：解析 CONNECT 并分别保留认证、EOF 与原生 I/O 失败。 */
        [[nodiscard]] auto ReadHandshake(std::string &Target)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Handshaken_ = false;
            Target.clear();
            if (!NextLayer_)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            std::array<std::uint8_t, 256> Chunk{};
            std::string Header;
            Prism::Fault::Failure ReadFailure;
            for (int Index = 0; Index < 16; ++Index)
            {
                const auto Part = co_await NextLayer_->ReadSome(AsBytes(std::span<std::uint8_t>(Chunk)));
                if (Part.Bytes > Chunk.size())
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
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
                    ReadFailure = {Prism::Fault::Code::Eof};
                    break;
                }
            }
            const auto HeaderEnd = Header.find("\r\n\r\n");
            if (HeaderEnd == std::string::npos)
            {
                if (ReadFailure.Failed()) co_return std::unexpected(ReadFailure);
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            const auto FirstLineEnd = Header.find("\r\n");
            if (FirstLineEnd == std::string::npos || FirstLineEnd > HeaderEnd ||
                Header.find("CONNECT ") != 0)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            const auto TargetLine = Header.substr(8, FirstLineEnd - 8);
            const auto Colon = TargetLine.find(':');
            Target = TargetLine;
            if (Colon != std::string::npos)
            {
                Target = TargetLine.substr(0, Colon);
            }
            const auto Auth = HeaderValue(Header, "Proxy-Authorization");
            if (!Auth || !VerifyBasicAuth(*Auth, User_, Pass_))
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::AuthFailed});
            Target_ = Target;
            PreserveHandshakeTail(Header, HeaderEnd + 4);
            Handshaken_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
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
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            if (Buffer.empty() || PendingOffset_ < PendingWire_.size())
            {
                Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), TakePending(Buffer));
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
         * @brief 清除握手状态并交付底层关闭
         * @return 命令接管成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Handshaken_ = false;
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
            Handshaken_ = false;
            Activity_->ReleaseChild();
            return std::move(NextLayer_);
        }

    private:
        /** @brief 去除 HTTP 首部字段边缘的空格与制表符。 */
        [[nodiscard]] static auto Trim(std::string_view Value) noexcept
            -> std::string_view
        {
            while (!Value.empty() &&
                   (Value.front() == ' ' || Value.front() == '\t'))
            {
                Value.remove_prefix(1);
            }
            while (!Value.empty() &&
                   (Value.back() == ' ' || Value.back() == '\t'))
            {
                Value.remove_suffix(1);
            }
            return Value;
        }

        /** @brief 按 ASCII 大小写不敏感比较 HTTP 首部名称。 */
        [[nodiscard]] static auto EqualInsensitive(
            std::string_view Left,
            std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                const auto Lower = [](char Character) noexcept -> char
                {
                    if (Character >= 'A' && Character <= 'Z')
                    {
                        return static_cast<char>(Character + ('a' - 'A'));
                    }
                    return Character;
                };
                if (Lower(Left[Index]) != Lower(Right[Index]))
                {
                    return false;
                }
            }
            return true;
        }

        /** @brief 从 HTTP 请求头读取指定字段并返回借用视图。 */
        [[nodiscard]] static auto HeaderValue(
            std::string_view Header,
            std::string_view Name) noexcept
            -> std::optional<std::string_view>
        {
            std::size_t Begin = 0;
            while (Begin < Header.size())
            {
                const auto End = Header.find("\r\n", Begin);
                if (End == std::string_view::npos)
                {
                    return std::nullopt;
                }
                const auto Line = Header.substr(Begin, End - Begin);
                if (Line.empty())
                {
                    return std::nullopt;
                }
                const auto Colon = Line.find(':');
                if (Colon != std::string_view::npos &&
                    EqualInsensitive(Trim(Line.substr(0, Colon)), Name))
                {
                    return Trim(Line.substr(Colon + 1));
                }
                Begin = End + 2;
            }
            return std::nullopt;
        }

        /** @brief 写完握手载荷并返回首个底层 typed failure。 */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                const auto Part = co_await NextLayer_->WriteSome(AsBytes(Data.subspan(Offset)));
                if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
                const auto Remaining = Data.size() - Offset;
                if (Part.Bytes == 0)
                    co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                if (Part.Bytes > Remaining)
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                Offset += Part.Bytes;
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 消费握手超读缓冲；空缓冲或已消费完返回 0 字节成功。 */
        [[nodiscard]] auto TakePending(std::span<std::byte> Buffer) -> Prism::IoResult
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
static_assert(Prism::TransmissionLike<Conn<>>);

} // namespace Prism::Trusttunnel::Detail
