/**
 * @file Conn.hpp
 * @brief Trojan 流连接对象（装饰器模式：内存策略模板化）
 * @details 单条 TCP 协议连接的完整状态：持有上游传输（所有权，
 * SharedTransmission 运行时多态）、预读缓冲、凭据。读写经虚接口
 * 静态委托给上游具体传输（内存流 / 可靠连接均满足 TransmissionLike）。
 * - 客户端：WriteHandshake 发送请求头（凭据 + 命令 + 地址）
 * - 服务端：ReadHandshake 解析校验请求头
 * UDP 数据面由 Dgram.hpp 提供（独立包连接类型，嵌入本连接）。
 * @note 对齐 mihomo transport：TCP 采用纯流传输语义。
 * @note 模板参数仅 Memory（会话内存策略：Arena 复用零分配），
 *      上游传输类型经 Transmission 虚接口擦除，装饰器链统一。
 */

#pragma once

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

#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>

namespace Preview::Trojan
{

    namespace Net = boost::asio;

    /**
     * @class Conn
     * @brief Trojan 流连接对象（装饰器模式）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @details 单条 TCP 连接的协议状态：握手（客户端写 / 服务端读）、
     * 数据透传、预读缓冲。读写经传输虚接口委托上游具体类型。
     * 由工厂（Connect / Accept）创建，调用方以 shared_ptr 持有。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 上游传输（所有权移交）
         * @param Password 协议密码（派生 SHA224 hex 凭据）
         * @param Auth 认证器（旧兼容裸指针；nullptr = 静态比对 password）
         * @param AuthOwner 认证器共享所有权（可选）
         */
        explicit Conn(
            SharedTransmission Upstream,
            std::string Password,
            const Preview::Authenticator *Auth = nullptr,
            Preview::SharedAuthenticator AuthOwner = {})
            : NextLayer_(std::move(Upstream)), AuthOwner_(std::move(AuthOwner)), Auth_(Auth)
        {
            if (AuthOwner_)
            {
                Auth_ = AuthOwner_.get();
            }
            Cred_ = Credential(Password);
        }

        /**
         * @brief 获取执行器（静态分派到上游）
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
         * @brief 异步读取（预读缓冲优先）
         * @param Buffer 接收缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 实际读取字节数
         * @details 握手阶段预读的剩余字节先被消费，清空后透传底层。
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (Used_ > 0)
            {
                const auto N = std::min(Buffer.size(), Used_);
                std::memcpy(Buffer.data(), Buf_.data(), N);
                if (N < Used_)
                {
                    std::memmove(Buf_.data(), Buf_.data() + N, Used_ - N);
                }
                else
                {
                    Buf_.clear();
                }
                Used_ -= N;
                co_return N;
            }
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 异步写入（静态分派透传）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (!NextLayer_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ErrorCode);
        }

        /**
         * @brief 异步读取直至缓冲区读满（组合操作）
         * @param Buffer 接收缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 实际读取字节数（满 = Buffer.size()；EOF 提前返回）
         */
        [[nodiscard]] auto AsyncRead(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto N = co_await async_read_some(Buffer.subspan(Done), ErrorCode);
                if (ErrorCode)
                {
                    co_return Done;
                }
                if (N == 0)
                {
                    co_return Done;
                }
                if (N > Buffer.size() - Done)
                {
                    ErrorCode = make_error_code(Error::BrokenPipe);
                    co_return Done;
                }
                Done += N;
            }
            co_return Done;
        }

        /**
         * @brief 异步写入直至缓冲区写满（组合操作）
         * @param Buffer 发送缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 实际写入字节数（满 = Buffer.size()）
         */
        [[nodiscard]] auto AsyncWrite(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto N = co_await async_write_some(Buffer.subspan(Done), ErrorCode);
                if (ErrorCode)
                {
                    co_return Done;
                }
                if (N == 0)
                {
                    ErrorCode = make_error_code(Error::BrokenPipe);
                    co_return Done;
                }
                if (N > Buffer.size() - Done)
                {
                    ErrorCode = make_error_code(Error::BrokenPipe);
                    co_return Done;
                }
                Done += N;
            }
            co_return Done;
        }

        /**
         * @brief 关闭传输层（静态分派）
         */
        auto Close() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作（静态分派）
         */
        auto Cancel() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept
            -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept
            -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

        /**
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return NextLayer_ != nullptr && Handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 Conn 存活，Conn 析构时一次性回收
         */
        [[nodiscard]] auto Arena() noexcept -> Preview::Memory::ResourcePointer
        {
            return Mem_.Arena();
        }

        /**
         * @brief 客户端握手：发送请求头（凭据 + 命令 + 地址）
         * @param Target 目标地址
         * @param Cmd 命令（CONNECT / udp_associate / mux）
         * @return 错误码
         * @details 构造并发送请求头，不读响应（对齐主库 trojan）。
         * 由工厂 Connect 内部调用。
         */
        [[nodiscard]] auto WriteHandshake(
            const Address &Target,
            Command Cmd = Command::Connect) -> Net::awaitable<Error>
        {
            if (Cmd != Command::Connect && Cmd != Command::UdpAssociate && Cmd != Command::Mux)
            {
                co_return Error::BadMessage;
            }
            const auto Wire = BuildRequest(Cred_, Cmd, Target);
            if (Wire.empty())
            {
                co_return Error::BadAddress;
            }
            const bool Failed = co_await SendBytes(Wire); // true = 发送失败
            Handshaken_ = !Failed;
            if (Failed)
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析请求头
         * @param EnableTcp 是否允许 CONNECT 命令
         * @param EnableUdp 是否允许 UDP_ASSOCIATE 命令
         * @return 错误码与解析的请求
         * @details 通过共享 Parser 增量读取并校验（凭据/CRLF/命令开关/atyp/尾部）。
         * 认证失败不发送响应，静默断开（对齐 trojan-gfw）。
         * 由工厂 Accept 内部调用。
         */
        [[nodiscard]] auto ReadHandshake(bool EnableTcp = true, bool EnableUdp = false,
                                         bool EnableMux = true)
            -> Net::awaitable<std::pair<Error, RequestHeader>>
        {
            Parser RequestParser("");
            RequestParser.SetCredential(Cred_, Auth_ == nullptr);
            std::error_code ParseError;
            const auto NeedMore = make_error_code(Error::NeedMore);
            while (!RequestParser.IsDone())
            {
                std::array<std::uint8_t, 1> Byte{};
                if (co_await ReadExactImpl(std::span<std::uint8_t>(Byte)))
                {
                    co_return std::pair{Error::IoError, RequestHeader{}};
                }
                ParseError.clear();
                RequestParser.Put(Net::const_buffer(Byte.data(), Byte.size()), ParseError);
                if (ParseError && ParseError != NeedMore)
                {
                    const auto ParserError = static_cast<Error>(ParseError.value());
                    co_return std::pair{
                        ParserError == Error::AuthFailed ? Error::BadAuth : ParserError,
                        RequestHeader{}};
                }
            }

            const auto Parsed = RequestParser.Get();
            const auto Cmd = Parsed.cmd;
            if (Cmd == Command::Mux && !EnableMux)
            {
                co_return std::pair{Error::NotSupported, RequestHeader{}};
            }
            if (Cmd == Command::Connect && !EnableTcp)
            {
                co_return std::pair{Error::NotSupported, RequestHeader{}};
            }
            if (Cmd == Command::UdpAssociate && !EnableUdp)
            {
                co_return std::pair{Error::NotSupported, RequestHeader{}};
            }

            if (Auth_)
            {
                const auto CredentialValue = RequestParser.CredentialValue();
                auto AuthenticationResult = Auth_->Authenticate(Preview::AuthenticationRequest{
                    .AccountId = {},
                    .Identity = {},
                    .Credential = Preview::Account::CredentialView::Token(CredentialValue),
                    .Rate = {}});
                if (!AuthenticationResult.Accepted)
                {
                    co_return std::pair{Error::BadAuth, RequestHeader{}};
                }
                AuthLease_ = std::move(AuthenticationResult.Lease);
                AccountId_ = AuthenticationResult.AccountId;
                Identity_ = std::move(AuthenticationResult.Identity);
            }

            RequestHeader RequestValue;
            RequestValue.Cmd = Cmd;
            RequestValue.Target = Parsed.dst;

            Request_ = RequestValue;
            Handshaken_ = true;
            co_return std::pair{Error::None, std::move(RequestValue)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Request() const -> const RequestHeader &
        {
            return Request_;
        }

        /**
         * @brief 转移协议认证产生的账户租约
         * @return 已认证账户租约；静态密码认证时为空
         */
        [[nodiscard]] auto TakeAuthLease() -> Preview::Account::AccountLease
        {
            return std::move(AuthLease_);
        }

        /** @brief 获取认证后的 typed 账户身份。 */
        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return AccountId_;
        }

        /** @brief 获取认证后的非敏感身份文本。 */
        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Identity_;
        }

        /**
         * @brief 精确分段读取（供包连接复用预读缓冲）
         * @param Buffer 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<bool>
        {
            return ReadExactImpl(Buffer);
        }

    private:
        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param Output 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &Output) -> Net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                Output,
                [this](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                {
                    return ReadExactImpl(Buffer);
                });
        }

        /**
         * @brief 精确读取指定字节数（内部缓冲优先 + 底层补充）
         * @param Buffer 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         * @details 超读字节保留在内部缓冲供后续消费。
         */
        [[nodiscard]] auto ReadExactImpl(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                if (Used_ > 0)
                {
                    const auto N = std::min(Buffer.size() - Done, Used_);
                    std::memcpy(Buffer.data() + Done, Buf_.data(), N);
                    if (N < Used_)
                    {
                        std::memmove(Buf_.data(), Buf_.data() + N, Used_ - N);
                        Used_ -= N;
                    }
                    else
                    {
                        Buf_.clear();
                        Used_ = 0;
                    }
                    Done += N;
                    continue;
                }
                if (!NextLayer_)
                {
                    co_return true;
                }
                std::array<std::uint8_t, 512> Chunk{};
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Chunk.data()), Chunk.size()), ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return true;
                }
                if (N > Chunk.size())
                {
                    co_return true;
                }
                Buf_.insert(Buf_.end(), Chunk.begin(), Chunk.begin() + static_cast<std::ptrdiff_t>(N));
                Used_ += N;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                if (!NextLayer_)
                {
                    co_return true;
                }
                std::error_code ErrorCode;
                ErrorCode.clear();
                const auto N = co_await NextLayer_->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data() + Done),
                                               Data.size() - Done),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return true;
                }
                if (N == 0)
                {
                    co_return true; // 底层零字节写入，防死循环
                }
                if (N > Data.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;              ///< 上游传输（基类传参，运行时多态）
        std::string Cred_;                            ///< 预计算凭据（SHA224 hex）
        Preview::SharedAuthenticator AuthOwner_{}; ///< 认证器共享所有权
        const Preview::Authenticator *Auth_{nullptr}; ///< 认证器（兼容裸指针）
        Preview::Account::AccountLease AuthLease_{}; ///< 协议认证租约
        Preview::AccountId AccountId_{};              ///< typed 账户身份
        std::string Identity_{};                      ///< 非敏感身份文本
        RequestHeader Request_;                      ///< 服务端握手解析结果
        Memory Mem_;                                  ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> Buf_{Mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t Used_{0};                                              ///< 缓冲中有效字节数
        bool Handshaken_{false};                                           ///< 握手完成标志
    };

    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    // 编译期验证：Conn 满足传输接口概念（可被其他协议工厂接收）
    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Trojan
