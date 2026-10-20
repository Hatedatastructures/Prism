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
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Trojan/AddressCodec.hpp>
#include <Prism/Protocols/Trojan/BeastCodec.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Trojan/UdpCodec.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>

namespace Prism::Trojan
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
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Conn : public Prism::Transmission
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 上游传输（所有权移交）
         * @param Password 协议密码（派生 SHA224 hex 凭据）
         * @param AuthOwner 认证器共享所有权
         */
        explicit Conn(
            SharedTransmission Upstream,
            std::string Password,
            Prism::SharedAuthenticator AuthOwner = {})
            : Prism::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream)), AuthOwner_(std::move(AuthOwner))
        {
            Cred_ = Credential(Password);
        }

        /**
         * @brief 获取执行器（静态分派到上游）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Prism::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 预读缓冲优先的部分读；结果与借用沿正式前门交付一次
         * @param Buffer 接收缓冲区（借用到 completion 返回）
         * @param Handler 正式完成；命中预读缓冲或上游已释放时异步交付
         * @details 握手阶段预读的剩余字节先被消费，清空后透传底层。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (Used_ > 0 || ReadTerminal_ || !NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), TakePending(Buffer));
                return;
            }
            const auto Limit = Buffer.size();
            NextLayer_->ReadSome(
                Buffer,
                [Limit, Handler = std::move(Handler)](Prism::IoResult Result) mutable
                {
                    if (Result.Bytes > Limit)
                    {
                        Result = {0, Prism::Fault::FromNative(
                                        Prism::make_error_code(Error::BrokenPipe))};
                    }
                    Handler(std::move(Result));
                });
        }

        /**
         * @brief 底层透传写入，保持短写语义
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            const auto Limit = Buffer.size();
            NextLayer_->WriteSome(
                Buffer,
                [Limit, Handler = std::move(Handler)](Prism::IoResult Result) mutable
                {
                    if (Result.Bytes > Limit)
                    {
                        Result = {0, Prism::Fault::FromNative(
                                        Prism::make_error_code(Error::BrokenPipe))};
                    }
                    Handler(std::move(Result));
                });
        }

        /** @brief 真实写半关闭转交底层载体；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /** @brief 可重复取消底层 I/O；成功不表示连接已关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept
            -> Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override
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
        [[nodiscard]] auto Arena() noexcept -> Prism::Memory::ResourcePointer
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
            Command Cmd = Command::Connect) -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (Cmd != Command::Connect && Cmd != Command::UdpAssociate && Cmd != Command::Mux)
            {
                co_return std::unexpected(Prism::Protocol::Common::FailureFromProtocolError(Error::BadMessage));
            }
            const auto Wire = BuildRequest(Cred_, Cmd, Target);
            if (Wire.empty())
            {
                co_return std::unexpected(Prism::Protocol::Common::FailureFromProtocolError(Error::BadAddress));
            }
            const auto Written = co_await Prism::Protocol::Common::WriteAllIo(NextLayer_, Wire);
            if (Written.Failure.Failed())
            {
                co_return std::unexpected(Prism::Protocol::Common::FailureFromIo(Written));
            }
            Handshaken_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
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
            -> Net::awaitable<std::expected<RequestHeader, Prism::Fault::Failure>>
        {
            Parser RequestParser("");
            RequestParser.SetCredential(Cred_, !AuthOwner_);
            std::error_code ParseError;
            const auto NeedMore = make_error_code(Error::NeedMore);
            while (!RequestParser.IsDone())
            {
                std::array<std::uint8_t, 1> Byte{};
                const auto Read = co_await ReadExactIo(Byte);
                if (Read.Failure.Failed())
                {
                    co_return std::unexpected(Prism::Protocol::Common::FailureFromIo(Read));
                }
                ParseError.clear();
                RequestParser.Put(Net::const_buffer(Byte.data(), Byte.size()), ParseError);
                if (ParseError && ParseError != NeedMore)
                {
                    const auto ParserError = static_cast<Error>(ParseError.value());
                    co_return std::unexpected(
                        Prism::Protocol::Common::FailureFromProtocolError(ParserError));
                }
            }

            const auto Parsed = RequestParser.Get();
            const auto Cmd = Parsed.Cmd;
            if (Cmd == Command::Mux && !EnableMux)
            {
                co_return std::unexpected(
                    Prism::Protocol::Common::FailureFromProtocolError(Error::Unsupported));
            }
            if (Cmd == Command::Connect && !EnableTcp)
            {
                co_return std::unexpected(
                    Prism::Protocol::Common::FailureFromProtocolError(Error::Unsupported));
            }
            if (Cmd == Command::UdpAssociate && !EnableUdp)
            {
                co_return std::unexpected(
                    Prism::Protocol::Common::FailureFromProtocolError(Error::Unsupported));
            }

            if (const auto *Authenticator = AuthOwner_.get())
            {
                const auto CredentialValue = RequestParser.CredentialValue();
                auto AuthenticationResult = Authenticator->Authenticate(Prism::AuthenticationRequest{
                    .AccountId = {},
                    .Identity = {},
                    .Credential = Prism::Account::CredentialView::Token(CredentialValue),
                    .Rate = {}});
                if (!AuthenticationResult)
                {
                    co_return std::unexpected(
                        Prism::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
                }
                AuthLease_ = std::move(*AuthenticationResult);
                AccountId_ = AuthLease_.AccountId();
                Identity_ = std::string(AuthLease_.Identity());
            }

            RequestHeader RequestValue;
            RequestValue.Cmd = Cmd;
            RequestValue.Target = Parsed.Target;

            Request_ = RequestValue;
            Handshaken_ = true;
            co_return RequestValue;
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
        [[nodiscard]] auto TakeAuthLease() -> Prism::Account::AccountLease
        {
            return std::move(AuthLease_);
        }

        /** @brief 获取认证后的 typed 账户身份。 */
        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            return AccountId_;
        }

        /** @brief 获取认证后的非敏感身份文本。 */
        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Identity_;
        }

    private:
        /** @brief 预读缓冲优先的真实部分读；内部精确读与协议前门共用同一实现。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            if (Used_ > 0 || ReadTerminal_)
            {
                co_return TakePending(Buffer);
            }
            if (!NextLayer_)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await NextLayer_->ReadSome(Buffer);
        }

        /** @brief 底层透传的真实部分写；失败与短写语义由底层定义。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            if (!NextLayer_)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await NextLayer_->WriteSome(Buffer);
        }

        /** @brief 消费预读缓冲；无缓冲或上游已释放时返回 0 字节与确定的领域失败码。 */
        [[nodiscard]] auto TakePending(std::span<std::byte> Buffer) -> Prism::IoResult
        {
            if (Used_ == 0)
            {
                if (ReadTerminal_)
                {
                    return {0, *ReadTerminal_};
                }
                return {0, {Prism::Fault::Code::IoError}};
            }
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
            return {N, {}};
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param Output 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &Output) -> Net::awaitable<Error>
        {
            return Prism::Trojan::ReadAddressBody(
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
            const auto Result = co_await ReadExactIo(Buffer);
            co_return Result.Failure.Failed() || Result.Bytes != Buffer.size();
        }

        /** @brief 精确读取字段，完整字节先交付并保留 overread 尾部与终态。 */
        [[nodiscard]] auto ReadExactIo(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            Prism::IoResult Result;
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
                    Result.Bytes = Done;
                    continue;
                }
                if (ReadTerminal_)
                {
                    Result.Failure = *ReadTerminal_;
                    co_return Result;
                }
                if (!NextLayer_)
                {
                    Result.Failure = {Prism::Fault::Code::IoError};
                    co_return Result;
                }
                std::array<std::uint8_t, 512> Chunk{};
                const auto Part = co_await NextLayer_->ReadSome(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Chunk.data()), Chunk.size()));
                if (Part.Bytes > Chunk.size())
                {
                    ReadTerminal_ = Prism::Fault::Failure{
                        Prism::Fault::Code::InvalidArgument, Part.Failure.Native};
                    Result.Failure = *ReadTerminal_;
                    co_return Result;
                }
                const auto Consumed = std::min(Buffer.size() - Done, Part.Bytes);
                if (Consumed != 0)
                {
                    std::memcpy(Buffer.data() + Done, Chunk.data(), Consumed);
                    Done += Consumed;
                    Result.Bytes = Done;
                }
                if (Part.Bytes > Consumed)
                {
                    Buf_.insert(
                        Buf_.end(), Chunk.begin() + static_cast<std::ptrdiff_t>(Consumed),
                        Chunk.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
                    Used_ += Part.Bytes - Consumed;
                }
                if (Part.Failure.Failed())
                {
                    ReadTerminal_ = Part.Failure;
                    if (Done == Buffer.size())
                    {
                        co_return Result;
                    }
                    Result.Failure = Part.Failure;
                    co_return Result;
                }
                if (Part.Bytes == 0)
                {
                    Result.Failure = {Prism::Fault::Code::WouldBlock};
                    co_return Result;
                }
            }
            co_return Result;
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
                const auto Part = co_await NextLayer_->WriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data() + Done),
                                               Data.size() - Done));
                if (Part.Failure.Failed())
                {
                    co_return true;
                }
                if (Part.Bytes == 0)
                {
                    co_return true; // 底层零字节写入，防死循环
                }
                if (Part.Bytes > Data.size() - Done)
                {
                    co_return true;
                }
                Done += Part.Bytes;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;              ///< 上游传输（基类传参，运行时多态）
        std::string Cred_;                            ///< 预计算凭据（SHA224 hex）
        Prism::SharedAuthenticator AuthOwner_{}; ///< 认证器共享所有权
        Prism::Account::AccountLease AuthLease_{}; ///< 协议认证租约
        Prism::AccountId AccountId_{};              ///< typed 账户身份
        std::string Identity_{};                      ///< 非敏感身份文本
        RequestHeader Request_;                      ///< 服务端握手解析结果
        Memory Mem_;                                  ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> Buf_{Mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t Used_{0};                                              ///< 缓冲中有效字节数
        std::optional<Prism::Fault::Failure> ReadTerminal_{}; ///< 缓存字节排空后的终态
        bool Handshaken_{false};                                           ///< 握手完成标志
    };

    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    // 编译期验证：Conn 满足传输接口概念（可被其他协议工厂接收）
    static_assert(Prism::TransmissionLike<Conn<>>);

} // namespace Prism::Trojan
