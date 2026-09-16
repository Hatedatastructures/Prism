/**
 * @file Conn.hpp
 * @brief Restls 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 Restls 连接：
 * 1. WriteHandshake / ReadHandshake：认证握手（测试库简化：
 *    交换 ServerRandom，客户端派生 Secret 校验服务端 mask）
 * 2. 数据面：应用数据记录带 auth_mac + XOR mask 编解码
 * @note 与 restls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Restls/Codec.hpp>
#include <Preview/Protocols/Restls/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Restls
{

    /**
     * @class Conn
     * @brief Restls 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面
     * 经 auth_mac + mask 编解码透传。
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
         * @param Password 认证密码
         */
        explicit Conn(SharedTransmission Upstream, std::string Password)
            : NextLayer_(std::move(Upstream)), Password_(std::move(Password))
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
         * @brief 客户端握手：派生 Secret 并交换 ServerRandom
         * @param ServerRandom 服务端随机数（32 字节）
         * @return 错误码
         * @details 客户端由密码派生 RestlsSecret，后续认证均以其为密钥。
         */
        [[nodiscard]] auto WriteHandshake(
            std::span<const std::uint8_t> ServerRandom) -> Net::awaitable<Error>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToServer, {});
        }

        /**
         * @brief 客户端握手并接管首个 ClientFinished
         * @param ServerRandom 服务端随机数
         * @param ClientFinished 首个客户端加密记录
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(
            std::span<const std::uint8_t> ServerRandom,
            std::span<const std::uint8_t> ClientFinished) -> Net::awaitable<Error>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToServer, ClientFinished);
        }

        /**
         * @brief 服务端握手：派生 Secret 并校验客户端身份
         * @param ServerRandom 服务端随机数（32 字节）
         * @return 错误码
         * @details 服务端同样派生 Secret，并以 ServerMask 加密
         * 首个 TLS 记录实现服务端身份验证（测试库简化直接派生）。
         */
        [[nodiscard]] auto ReadHandshake(
            std::span<const std::uint8_t> ServerRandom) -> Net::awaitable<Error>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToClient, {});
        }

        /**
         * @brief 服务端握手并接管首个 ClientFinished
         * @param ServerRandom 服务端随机数
         * @param ClientFinished 首个客户端加密记录
         * @return 错误码
         */
        [[nodiscard]] auto ReadHandshake(
            std::span<const std::uint8_t> ServerRandom,
            std::span<const std::uint8_t> ClientFinished) -> Net::awaitable<Error>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToClient, ClientFinished);
        }

        /**
         * @brief 透传读取（数据面原样，mask 编解码由上层记录层负责）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                SetError(ErrorCode, Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }

            while (true)
            {
                if (PendingReadOffset_ < PendingReadPayload_.size())
                {
                    const auto Count = (std::min)(Buffer.size(),
                                                  PendingReadPayload_.size() - PendingReadOffset_);
                    std::memcpy(Buffer.data(), PendingReadPayload_.data() + PendingReadOffset_, Count);
                    PendingReadOffset_ += Count;
                    if (PendingReadOffset_ == PendingReadPayload_.size())
                    {
                        PendingReadPayload_.clear();
                        PendingReadOffset_ = 0;
                    }
                    co_return Count;
                }

                std::array<std::uint8_t, TlsHdrlen> Header{};
                const auto HeaderError = co_await ReadExact(Header);
                if (HeaderError != Error::None)
                {
                    SetError(ErrorCode, HeaderError);
                    co_return 0;
                }
                const auto PayloadLength = (static_cast<std::size_t>(Header[3]) << 8U) | Header[4];
                if (PayloadLength < AuthHdrlen || PayloadLength > MaxRecordPayload)
                {
                    SetError(ErrorCode, Error::BadLength);
                    co_return 0;
                }

                std::vector<std::uint8_t> Wire(TlsHdrlen + PayloadLength);
                std::copy(Header.begin(), Header.end(), Wire.begin());
                const auto PayloadError = co_await ReadExact(
                    std::span<std::uint8_t>(Wire).subspan(TlsHdrlen));
                if (PayloadError != Error::None)
                {
                    SetError(ErrorCode, PayloadError);
                    co_return 0;
                }

                const auto ClientFinished =
                    ReadDirection_ == FlowDirection::ToServer
                        ? std::span<const std::uint8_t>(ClientFinished_)
                        : std::span<const std::uint8_t>{};
                DecodedFrame Decoded;
                const auto DecodeError = DecodeFrame(
                    Wire,
                    DecodeOptions{.Secret = Secret_,
                                  .ServerRandom = ServerRandom_,
                                  .Direction = ReadDirection_,
                                  .Counter = ReadCounter_,
                                  .ClientFinished = ClientFinished},
                    Decoded);
                if (DecodeError != Error::None)
                {
                    SetError(ErrorCode, DecodeError);
                    co_return 0;
                }

                ++ReadCounter_;
                if (ReadDirection_ == FlowDirection::ToServer && !ClientFinished_.empty())
                {
                    ClientFinished_.clear();
                }
                PendingReadPayload_ = std::move(Decoded.Data);
                PendingReadOffset_ = 0;
                if (PendingReadPayload_.empty())
                {
                    continue;
                }
            }
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
                SetError(ErrorCode, Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }

            const auto Count = (std::min)(Buffer.size(), MaxDataLength);
            std::vector<std::uint8_t> Data(Count);
            std::memcpy(Data.data(), Buffer.data(), Count);
            const auto ClientFinished =
                WriteDirection_ == FlowDirection::ToServer
                    ? std::span<const std::uint8_t>(ClientFinished_)
                    : std::span<const std::uint8_t>{};
            const auto [BuildError, Wire] = BuildFrame(FrameOptions{
                .Secret = Secret_,
                .ServerRandom = ServerRandom_,
                .Direction = WriteDirection_,
                .Counter = WriteCounter_,
                .ClientFinished = ClientFinished,
                .Data = Data,
                .PaddingLength = 0,
                .Command = CmdTypeNoop,
                .CommandArgument = 0});
            if (BuildError != Error::None)
            {
                SetError(ErrorCode, BuildError);
                co_return 0;
            }

            if (!co_await SendAll(Wire, ErrorCode))
            {
                co_return 0;
            }
            ++WriteCounter_;
            if (WriteDirection_ == FlowDirection::ToServer && !ClientFinished_.empty())
            {
                ClientFinished_.clear();
            }
            co_return Count;
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

        /**
         * @brief 获取派生密钥（握手后有效）
         */
        [[nodiscard]] auto Secret() const -> const std::array<std::uint8_t, 32> &
        {
            return Secret_;
        }

    private:
        [[nodiscard]] auto Initialize(
            std::span<const std::uint8_t> ServerRandom,
            const FlowDirection WriteDirection,
            std::span<const std::uint8_t> ClientFinished) -> Error
        {
            Handshaken_ = false;
            if (!NextLayer_)
            {
                return Error::NotOpen;
            }
            if (ServerRandom.size() != ServerRandom_.size())
            {
                return Error::BadLength;
            }
            Secret_ = DeriveSecret(Password_);
            std::copy(ServerRandom.begin(), ServerRandom.end(), ServerRandom_.begin());
            WriteDirection_ = WriteDirection;
            ReadDirection_ = WriteDirection == FlowDirection::ToServer
                                 ? FlowDirection::ToClient
                                 : FlowDirection::ToServer;
            ClientFinished_.assign(ClientFinished.begin(), ClientFinished.end());
            ReadCounter_ = 0;
            WriteCounter_ = 0;
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            Handshaken_ = true;
            return Error::None;
        }

        [[nodiscard]] static auto MapNativeError(const std::error_code &ErrorCode) noexcept -> Error
        {
            if (!ErrorCode)
            {
                return Error::None;
            }
            if (ErrorCode == std::make_error_code(std::errc::operation_canceled))
            {
                return Error::Canceled;
            }
            if (ErrorCode == std::make_error_code(std::errc::timed_out))
            {
                return Error::Timeout;
            }
            return Error::IoError;
        }

        static auto SetError(std::error_code &Output, const Error ErrorValue) -> void
        {
            if (ErrorValue == Error::None)
            {
                Output.clear();
                return;
            }
            Output = std::error_code(static_cast<int>(ErrorValue), std::generic_category());
        }

        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<Error>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                std::error_code ErrorCode;
                const auto Read = co_await NextLayer_->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data() + Offset),
                                         Buffer.size() - Offset),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return MapNativeError(ErrorCode);
                }
                if (Read == 0 || Read > Buffer.size() - Offset)
                {
                    co_return Error::UnexpectedEof;
                }
                Offset += Read;
            }
            co_return Error::None;
        }

        [[nodiscard]] auto SendAll(std::span<const std::uint8_t> Buffer,
                                   std::error_code &ErrorCode)
            -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                const auto Written = co_await NextLayer_->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Buffer.data() + Offset),
                        Buffer.size() - Offset),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return false;
                }
                if (Written == 0 || Written > Buffer.size() - Offset)
                {
                    ErrorCode = std::make_error_code(std::errc::io_error);
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }

        SharedTransmission NextLayer_;                ///< 底层传输（独占所有权）
        std::string Password_;                          ///< 认证密码
        std::array<std::uint8_t, 32> Secret_{};         ///< RestlsSecret（派生）
        std::array<std::uint8_t, 32> ServerRandom_{};  ///< 服务端随机数
        std::vector<std::uint8_t> ClientFinished_;      ///< 首个客户端加密记录
        FlowDirection WriteDirection_{FlowDirection::ToServer}; ///< 写方向
        FlowDirection ReadDirection_{FlowDirection::ToClient};  ///< 读方向
        std::uint64_t ReadCounter_{0};                  ///< 读方向记录计数器
        std::uint64_t WriteCounter_{0};                 ///< 写方向记录计数器
        std::vector<std::uint8_t> PendingReadPayload_;  ///< 尚未交给调用方的明文
        std::size_t PendingReadOffset_{0};              ///< 明文消费游标
        bool Handshaken_{false};                        ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Restls
