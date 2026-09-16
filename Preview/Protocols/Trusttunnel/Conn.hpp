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
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Trusttunnel/Codec.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>

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
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Trusttunnel
{

    /**
     * @class Conn
     * @brief TrustTunnel 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission,
                 public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;
        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         * @param User 认证用户名
         * @param Password 认证密码
         */
        explicit Conn(
            SharedTransmission Upstream,
            std::string User,
            std::string Password)
            : NextLayer_(std::move(Upstream)), User_(std::move(User)), Pass_(std::move(Password))
        {
        }

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

        /**
         * @brief 客户端握手：发送 CONNECT 请求头
         * @param Target 目标主机
         * @param Port 目标端口
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(
            std::string_view Target,
            std::uint16_t Port) -> Net::awaitable<Error>
        {
            Handshaken_ = false;
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            const auto Auth = BasicAuth(User_, Pass_);
            std::string Header;
            Header.reserve(64 + Target.size() + Auth.size());
            Header += "CONNECT " + std::string(Target) + ":" + std::to_string(Port) + " HTTP/2\r\n";
            Header += "Proxy-Authorization: " + Auth + "\r\n";
            Header += "\r\n";
            if (co_await SendBytes(AsU8Span(Header)))
                co_return Error::IoError;
            Target_ = std::string(Target);
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析 CONNECT 请求并校验认证
         * @param Target 输出目标主机
         * @return 错误码；bad_auth = 认证失败
         */
        [[nodiscard]] auto ReadHandshake(std::string &Target) -> Net::awaitable<Error>
        {
            Handshaken_ = false;
            Target.clear();
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            // 读取头块（简化：读到空行）
            std::array<std::uint8_t, 256> Chunk{};
            std::string Header;
            bool FoundEnd = false;
            for (int I = 0; I < 16; ++I)
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(Chunk)), ErrorCode);
                if (N > Chunk.size())
                {
                    co_return Error::BadLength;
                }
                if (ErrorCode || N == 0)
                    break;
                Header.append(reinterpret_cast<const char *>(Chunk.data()), N);
                if (Header.find("\r\n\r\n") != std::string::npos)
                {
                    FoundEnd = true;
                    break;
                }
            }
            const auto HeaderEnd = Header.find("\r\n\r\n");
            if (!FoundEnd || HeaderEnd == std::string::npos)
                co_return Error::BadMagic;
            const auto FirstLineEnd = Header.find("\r\n");
            if (FirstLineEnd == std::string::npos || FirstLineEnd > HeaderEnd ||
                Header.find("CONNECT ") != 0)
                co_return Error::BadMagic;

            // 解析目标与认证
            const auto TargetLine = Header.substr(8, FirstLineEnd - 8);
            const auto Colon = TargetLine.find(':');
            if (Colon != std::string::npos)
                Target = TargetLine.substr(0, Colon);
            else
                Target = TargetLine;

            const auto Auth = HeaderValue(Header, "Proxy-Authorization");
            if (!Auth)
                co_return Error::BadAuth;
            if (!VerifyBasicAuth(*Auth, User_, Pass_))
                co_return Error::BadAuth;

            Target_ = Target;
            PreserveHandshakeTail(Header, HeaderEnd + 4);
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }
            if (PendingOffset_ < PendingWire_.size())
            {
                const auto Count = (std::min)(Buffer.size(), PendingWire_.size() - PendingOffset_);
                std::memcpy(Buffer.data(), PendingWire_.data() + PendingOffset_, Count);
                PendingOffset_ += Count;
                if (PendingOffset_ == PendingWire_.size())
                {
                    PendingWire_.clear();
                    PendingOffset_ = 0;
                }
                co_return Count;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            co_return co_await NextLayer_->async_write_some(Buffer, ErrorCode);
        }

        /**
         * @brief 关闭底层传输
         */
        auto Close() -> void override
        {
            Handshaken_ = false;
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        auto Cancel() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
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
            return std::move(NextLayer_);
        }

    private:
        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(Data.subspan(Done)), ErrorCode);
                if (ErrorCode || N == 0 || N > Data.size() - Done)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        [[nodiscard]] static auto Trim(std::string_view Value) noexcept -> std::string_view
        {
            while (!Value.empty() && (Value.front() == ' ' || Value.front() == '\t'))
            {
                Value.remove_prefix(1);
            }
            while (!Value.empty() && (Value.back() == ' ' || Value.back() == '\t'))
            {
                Value.remove_suffix(1);
            }
            return Value;
        }

        [[nodiscard]] static auto EqualInsensitive(std::string_view Left,
                                                   std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                const auto Lower = [](const char Character) noexcept -> char
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

        [[nodiscard]] static auto HeaderValue(std::string_view Header,
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

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        std::string User_;                ///< 认证用户名
        std::string Pass_;                ///< 认证密码
        std::string Target_;              ///< CONNECT 目标（握手后）
        bool Handshaken_{false};          ///< 握手完成标志
        std::vector<std::byte> PendingWire_; ///< 握手读取时回注的后续数据
        std::size_t PendingOffset_{0};       ///< 回注数据消费位置
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Trusttunnel
