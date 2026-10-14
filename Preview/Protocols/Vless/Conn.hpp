/**
 * @file Conn.hpp
 * @brief VLESS 流连接对象（TCP，实现 Transmission）
 * @details 单条 VLESS 连接的完整协议状态：
 * - 客户端握手：WriteHandshake(Target, Cmd)（发送请求头 →
 *   读取 2 字节响应校验 Version 回显）
 * - 服务端握手：ReadHandshake()（四段精确解析：固定前缀 →
 *   Addons → 尾部 → 地址体，校验 version/uuid/cmd/atyp，
 *   发送 2 字节响应）
 * 握手后为纯字节流透传（预读缓冲优先）。UDP 数据面由 Dgram.hpp
 * 提供（独立包连接类型，嵌入本连接）。
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
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    namespace Net = boost::asio;

    /**
     * @class Conn
     * @brief VLESS 流连接对象
     * @details 单条连接的协议状态：双端握手、数据透传、预读缓冲。
     * 实现 Transmission 接口可挂载装饰器链。由工厂创建，
     * 调用方以 shared_ptr 持有。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 上游传输（所有权移交）
         * @param Uuid 协议 UUID（16 字节，凭据/校验用）
         * @param AuthOwner 认证器共享所有权
         */
        explicit Conn(
            SharedTransmission Upstream,
            std::array<std::uint8_t, UuidLen> Uuid,
            Preview::SharedAuthenticator AuthOwner = {})
            : Preview::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream)), Uuid_(Uuid), AuthOwner_(std::move(AuthOwner))
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Preview::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 预读缓冲优先的部分读；结果与借用沿正式前门交付一次
         * @param Buffer 接收缓冲区（借用到 completion 返回）
         * @param Handler 正式完成；命中预读缓冲或上游已释放时异步交付
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (Used_ > 0 || !NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), TakePending(Buffer));
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 底层透传写入，保持短写语义
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
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
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
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
         * @brief 客户端握手：发送请求头 + 读取 2 字节响应
         * @param Target 目标地址
         * @param Cmd 命令（默认 Tcp；UDP 场景传 Udp）
         * @return 错误码
         * @details 构造请求头（version/uuid/cmd/Target）发送，
         * 读取 2 字节响应校验 Version 回显（对齐 Xray）。
         */
        [[nodiscard]] auto WriteHandshake(
            const Address &Target,
            Command Cmd = Command::Tcp) -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (Cmd != Command::Tcp && Cmd != Command::Udp && Cmd != Command::Mux)
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::BadMessage));
            }
            RequestHeader RequestValue;
            RequestValue.Version = ProtocolVersion;
            RequestValue.Uuid = Uuid_;
            RequestValue.Cmd = Cmd;
            RequestValue.Target = Target;
            const auto Wire = BuildRequest(RequestValue);
            if (Wire.empty())
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::BadAddress));
            }
            const auto Written = co_await Preview::Protocol::Common::WriteAllIo(NextLayer_, Wire);
            if (Written.Failure.Failed())
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromIo(Written));
            }

            std::array<std::uint8_t, 2> Response{};
            const auto Read = co_await Preview::Protocol::Common::ReadExactIo(NextLayer_, Response);
            if (Read.Failure.Failed())
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromIo(Read));
            }
            if (Response[0] != ProtocolVersion)
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::BadMagic));
            }
            if (Response[1] != 0x00)
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::BadMessage));
            }
            Handshaken_ = true;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /**
         * @brief 服务端握手：四段解析请求头 + 校验 + 发送响应
         * @param EnableTcp 是否允许 TCP 命令
         * @param EnableUdp 是否允许 UDP 命令
         * @param EnableMux 保留兼容参数；TCP handler 不暴露 MUX 数据面
         * @return 错误码与解析的请求
         * @details 精确分段读取（固定前缀 18B → Addons → 尾部 4B →
         * 地址体），校验 version/addnl/uuid/cmd/atyp。认证失败
         * （UUID 不匹配）不发送响应，静默断开（对齐 Xray）。
         */
        [[nodiscard]] auto ReadHandshake(bool EnableTcp = true, bool EnableUdp = true,
                                          bool EnableMux = true)
            -> Net::awaitable<std::expected<RequestHeader, Preview::Fault::Failure>>
        {
            // 认证器只负责凭据映射；wire 结构和命令边界统一由共享 Parser 解析。
            Parser RequestParser(Uuid_, !AuthOwner_);
            std::error_code ParseError;
            const auto NeedMore = make_error_code(Error::NeedMore);
            while (!RequestParser.IsDone())
            {
                std::array<std::uint8_t, 1> Byte{};
                const auto Read = co_await Preview::Protocol::Common::ReadExactIo(NextLayer_, Byte);
                if (Read.Failure.Failed())
                {
                    co_return std::unexpected(Preview::Protocol::Common::FailureFromIo(Read));
                }
                ParseError.clear();
                RequestParser.Put(Net::const_buffer(Byte.data(), Byte.size()), ParseError);
                if (ParseError && ParseError != NeedMore)
                {
                    const auto ParserError = static_cast<Error>(ParseError.value());
                    co_return std::unexpected(
                        Preview::Protocol::Common::FailureFromProtocolError(ParserError));
                }
            }

            const auto Parsed = RequestParser.Get();
            const auto Cmd = static_cast<Command>(Parsed.cmd);
            if ((Cmd == Command::Tcp && !EnableTcp) || (Cmd == Command::Udp && !EnableUdp) ||
                (Cmd == Command::Mux && !EnableMux))
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::Unsupported));
            }

            RequestHeader RequestValue;
            RequestValue.Version = ProtocolVersion;
            RequestValue.Uuid = Parsed.uuid;
            RequestValue.Cmd = Cmd;
            RequestValue.Target = Parsed.dst;

            if (const auto *Authenticator = AuthOwner_.get())
            {
                auto AuthenticationResult = Authenticator->Authenticate(Preview::AuthenticationRequest{
                    .AccountId = {},
                    .Identity = {},
                    .Credential = Preview::Account::CredentialView{
                        Preview::Account::CredentialKind::Uuid,
                        std::as_bytes(std::span<const std::uint8_t>(RequestValue.Uuid))},
                    .Rate = {}});
                if (!AuthenticationResult)
                {
                    co_return std::unexpected(
                        Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
                }
                AuthLease_ = std::move(*AuthenticationResult);
                AccountId_ = AuthLease_.AccountId();
                Identity_ = std::string(AuthLease_.Identity());
            }

            // 发送 2 字节响应 [Version 0x00][Addons Length 0x00]
            const auto Resp = MakeResponse();
            const auto Written = co_await Preview::Protocol::Common::WriteAllIo(NextLayer_, Resp);
            if (Written.Failure.Failed())
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromIo(Written));
            }

            Parsed_ = RequestValue;
            Handshaken_ = true;
            co_return RequestValue;
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const RequestHeader &
        {
            return Parsed_;
        }

        /**
         * @brief 转移协议认证产生的账户租约
         * @return 已认证账户租约；无目录认证时为空
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
        /** @brief 消费预读缓冲；无缓冲或上游已释放时返回 0 字节与确定的领域失败码。 */
        [[nodiscard]] auto TakePending(std::span<std::byte> Buffer) -> Preview::IoResult
        {
            if (Used_ == 0)
            {
                return {0, {Preview::Fault::Code::IoError}};
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
         * @brief 读取地址体（ATYP 已从尾部解析）
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
                const auto Part = co_await NextLayer_->ReadSome(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Chunk.data()), Chunk.size()));
                if (Part.Failure.Failed() || Part.Bytes == 0 || Part.Bytes > Chunk.size())
                {
                    co_return true;
                }
                Buf_.insert(Buf_.end(), Chunk.begin(), Chunk.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
                Used_ += Part.Bytes;
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
                const auto Part = co_await NextLayer_->WriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data() + Done),
                                               Data.size() - Done));
                if (Part.Failure.Failed())
                {
                    co_return true;
                }
                if (Part.Bytes == 0 || Part.Bytes > Data.size() - Done)
                {
                    co_return true; // 底层零字节写入，防死循环
                }
                Done += Part.Bytes;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;          ///< 上游传输（独占所有权）
        std::array<std::uint8_t, UuidLen> Uuid_; ///< 协议 UUID（凭据/校验）
        Preview::SharedAuthenticator AuthOwner_{}; ///< 认证器共享所有权
        Preview::Account::AccountLease AuthLease_{}; ///< 协议认证租约
        Preview::AccountId AccountId_{};              ///< typed 账户身份
        std::string Identity_{};                      ///< 非敏感身份文本
        RequestHeader Parsed_;                   ///< 服务端握手解析结果
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> Buf_{Mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t Used_{0};                     ///< 缓冲中有效字节数
        bool Handshaken_{false};         ///< 握手完成标志
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Vless
