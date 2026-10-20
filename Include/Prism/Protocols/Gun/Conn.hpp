/**
 * @file Conn.hpp
 * @brief gRPC (gun) 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 gun 连接（对齐 mihomo transport/gun）：
 * 1. WriteHandshake / ReadHandshake：HTTP/2 CONNECT 握手（简化）
 * 2. 数据面：gun-lite 模式裸透传（帧编解码由上层 h2 会话负责，
 *    Codec.hpp 纯函数供需要帧边界的测试直接使用）
 * @note 与 Gun.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Gun/Codec.hpp>
#include <Prism/Protocols/Gun/CodecTypes.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Gun
{

    /**
     * @class Conn
     * @brief gRPC (gun) 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Conn : public Prism::Transmission
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         */
        explicit Conn(SharedTransmission Upstream, Config ConfigValue = {})
            : Prism::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream)), Config_(std::move(ConfigValue))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Prism::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /** @brief 客户端握手：发送 CONNECT 请求并保留传输的 typed 失败。 */
        [[nodiscard]] auto WriteHandshake(std::string_view Host)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            Handshaken_ = false;
            PendingWire_.clear();
            PendingOffset_ = 0;
            PendingFailure_ = {};
            std::string Header = "CONNECT " + std::string(Host) + " HTTP/2\r\n";
            if (!Config_.Path.empty()) Header += ":path: " + Config_.Path + "\r\n";
            if (!Config_.ServiceName.empty()) Header += ":service: " + Config_.ServiceName + "\r\n";
            Header += "\r\n";
            const auto Sent = co_await SendBytes(AsU8Span(Header));
            if (!Sent) co_return std::unexpected(Sent.error());
            Handshaken_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 服务端握手：解析 CONNECT 帧并保留 EOF、取消与原生 I/O cause。 */
        [[nodiscard]] auto ReadHandshake(std::string &Host)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            Handshaken_ = false;
            PendingWire_.clear();
            PendingOffset_ = 0;
            PendingFailure_ = {};
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
                if (Part.Failure.Failed())
                {
                    ReadFailure = Part.Failure;
                    PendingFailure_ = Part.Failure;
                }
                if (Header.find("\r\n\r\n") != std::string::npos) break;
                if (ReadFailure.Failed())
                {
                    break;
                }
                if (Part.Bytes == 0)
                {
                    ReadFailure = {Prism::Fault::Code::Eof};
                    PendingFailure_ = ReadFailure;
                    break;
                }
            }
            const auto HeaderEnd = Header.find("\r\n\r\n");
            if (HeaderEnd == std::string::npos)
            {
                if (ReadFailure.Failed()) co_return std::unexpected(ReadFailure);
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            if (Header.find("CONNECT ") != 0)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            const auto FirstLineEnd = Header.find("\r\n");
            if (FirstLineEnd == std::string::npos || FirstLineEnd > HeaderEnd)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            const auto HostEnd = Header.find(' ', 8);
            if (HostEnd == std::string::npos || HostEnd > FirstLineEnd || HostEnd == 8)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            Host = Header.substr(8, HostEnd - 8);
            if ((!Config_.Path.empty() && HeaderValue(Header, ":path") != Config_.Path) ||
                (!Config_.ServiceName.empty() && HeaderValue(Header, ":service") != Config_.ServiceName))
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
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
            if (!NextLayer_ || (!Handshaken_ && !PendingFailure_.Failed()))
            {
                Prism::Transmission::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            if (Buffer.empty() || PendingOffset_ < PendingWire_.size())
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), TakePending(Buffer));
                return;
            }
            if (PendingFailure_.Failed())
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler), Prism::IoResult{0, PendingFailure_});
                return;
            }
            if (!Handshaken_)
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
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
                Prism::Transmission::PostResult(
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
                Prism::Transmission::PostResult(
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
            return std::move(NextLayer_);
        }

    private:
        /** @brief 写完握手载荷并保留原始部分写失败。 */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                const auto Part = co_await NextLayer_->WriteSome(AsBytes(Data.subspan(Offset)));
                if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
                const auto Remaining = Data.size() - Offset;
                if (Part.Bytes == 0)
                    co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                if (Part.Bytes > Remaining)
                    co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
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

        [[nodiscard]] static auto HeaderValue(std::string_view Header,
                                               std::string_view Name) noexcept
            -> std::string_view
        {
            std::size_t Begin = 0;
            while (Begin < Header.size())
            {
                const auto End = Header.find("\r\n", Begin);
                if (End == std::string_view::npos)
                {
                    return {};
                }
                const auto Line = Header.substr(Begin, End - Begin);
                const auto Prefix = std::string(Name) + ":";
                if (Line.starts_with(Prefix))
                {
                    auto Value = Line.substr(Prefix.size());
                    while (!Value.empty() && (Value.front() == ' ' || Value.front() == '\t'))
                    {
                        Value.remove_prefix(1);
                    }
                    return Value;
                }
                Begin = End + 2;
            }
            return {};
        }

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        Config Config_;
        bool Handshaken_{false};          ///< 握手完成标志
        std::vector<std::byte> PendingWire_; ///< 握手读取时回注的后续数据
        std::size_t PendingOffset_{0};       ///< 回注数据消费位置
        Prism::Fault::Failure PendingFailure_{}; ///< 握手同读终态在预读数据后 sticky 交付
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Prism::TransmissionLike<Conn<>>);

} // namespace Prism::Gun
