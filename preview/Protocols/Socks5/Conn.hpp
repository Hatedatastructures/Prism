/**
 * @file Conn.hpp
 * @brief SOCKS5 流连接对象（TCP，实现 Transmission）
 * @details 单条 SOCKS5 连接的完整协议状态：
 * - 客户端握手：WriteHandshake(RequestValue)（Greeting → 方法选择 → 认证 →
 *   请求 → 响应校验），成功后 BindEndpoint() 可取 BND 地址
 * - 服务端握手：ReadHandshake(Config)（Greeting → 方法协商 → 认证 →
 *   请求解析 → 响应），返回解析的请求
 * 握手后为纯字节流透传（预读缓冲优先）。UDP 数据面由 Dgram.hpp
 * 提供（独立包连接类型，嵌入本连接）。
 * @note 对齐 mihomo transport：TCP 采用纯流传输语义。
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
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Protocols/Common/Address.hpp>

#include <preview/Foundation/Authenticator.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    /**
     * @class Conn
     * @brief SOCKS5 流连接对象
     * @details 单条连接的协议状态：双端握手、数据透传、预读缓冲、
     * 认证状态。实现 Transmission 接口可挂载装饰器链。
     * 由工厂创建，调用方以 shared_ptr 持有。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 上游传输（所有权移交）
         */
        explicit Conn(SharedTransmission Upstream) : NextLayer_(std::move(Upstream))
        {
        }

        /**
         * @brief 获取执行器
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
         * @brief 异步写入（透传）
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
         * @brief 关闭传输层
         */
        auto Close() -> void override
        {
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
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return NextLayer_ != nullptr && Handshaken_;
        }

        /**
         * @brief 获取底层传输共享引用
         * @return 底层传输共享指针；空连接返回空指针
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        /**
         * @brief 获取底层传输共享引用（const 版本）
         * @return 底层传输共享指针；空连接返回空指针
         */
        [[nodiscard]] auto Underlying() const noexcept -> SharedTransmission
        {
            return NextLayer_;
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
         * @brief 客户端握手：Greeting → 方法选择 → 认证 → 请求 → 响应
         * @param RequestValue 目标请求（命令 + Target）
         * @param Config 客户端认证配置
         * @return 错误码
         * @details 完整客户端流程（RFC 1928 + 1929）。成功后 BND
         * 地址可通过 BindEndpoint() 获取（UDP_ASSOCIATE 用）。
         */
        [[nodiscard]] auto WriteHandshake(
            const Request &RequestValue,
            const ClientConfig &Config) -> Net::awaitable<Error>
        {
            const auto &EnableAuth = Config.EnableAuth;
            const auto &Username = Config.username;
            const auto &Password = Config.password;
            // 1. 发送 Greeting
            Greeting GreetingValue;
            GreetingValue.Ver = Version;
            if (EnableAuth)
            {
                GreetingValue.Methods =
                    std::vector<std::uint8_t>{static_cast<std::uint8_t>(AuthMethod::UserPass)};
            }
            else
            {
                GreetingValue.Methods =
                    std::vector<std::uint8_t>{static_cast<std::uint8_t>(AuthMethod::NoAuth)};
            }
            BuildGreeting(GreetingValue, TxWire_);
            if (TxWire_.empty())
            {
                co_return Error::BadLength;
            }
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::IoError;
            }

            // 2. 读取方法选择
            std::array<std::uint8_t, 2> Selection{};
            if (co_await ReadExact(std::span<std::uint8_t>(Selection)))
            {
                co_return Error::IoError;
            }
            if (Selection[0] != Version)
            {
                co_return Error::VersionMismatch;
            }
            std::uint8_t ExpectedMethod;
            if (EnableAuth)
            {
                ExpectedMethod = static_cast<std::uint8_t>(AuthMethod::UserPass);
            }
            else
            {
                ExpectedMethod = static_cast<std::uint8_t>(AuthMethod::NoAuth);
            }
            if (Selection[1] != ExpectedMethod)
            {
                // 客户端只允许配置所声明的方法，禁止服务端把认证连接降级为 NOAUTH，
                // 也不接受未声明的扩展方法。
                co_return Error::NotSupported;
            }

            // 3. 认证（如需，RFC 1929）
            if (Selection[1] == static_cast<std::uint8_t>(AuthMethod::UserPass))
            {
                BuildUserpass(Username, Password, TxWire_);
                if (TxWire_.empty())
                {
                    co_return Error::BadLength;
                }
                if (co_await SendBytes(TxWire_))
                {
                    co_return Error::IoError;
                }
                std::array<std::uint8_t, 2> Response{};
                if (co_await ReadExact(std::span<std::uint8_t>(Response)))
                {
                    co_return Error::IoError;
                }
                if (Response[0] != 0x01 || Response[1] != 0x00)
                {
                    co_return Error::BadAuth;
                }
            }

            // 4. 发送请求
            BuildRequest(RequestValue, TxWire_);
            if (TxWire_.empty())
            {
                co_return Error::BadAddress;
            }
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::IoError;
            }

            // 5. 读取响应并校验
            Reply ReplyValue;
            const auto ErrorCode = co_await ReadReply(ReplyValue);
            if (ErrorCode != Error::None)
            {
                co_return ErrorCode;
            }
            if (ReplyValue.Code != ReplyCode::Success)
            {
                co_return Error::BadAuth;
            }
            Bind_ = ReplyValue.Bind;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：Greeting → 方法协商 → 认证 → 请求 → 响应
         * @param Config 服务端命令与认证配置
         * @return 错误码与解析的请求
         * @details 完整服务端流程（RFC 1928 + 1929）。失败时按协议
         * 发送对应错误响应。
         */
        [[nodiscard]] auto ReadHandshake(const ServerConfig &Config)
            -> Net::awaitable<std::pair<Error, Request>>
        {
            const auto &EnableTcp = Config.EnableTcp;
            const auto &EnableUdp = Config.EnableUdp;
            const auto &EnableAuth = Config.EnableAuth;
            const auto &Username = Config.username;
            const auto &Password = Config.password;
            // 1. 方法协商：读取 Greeting（2B 头 + 方法列表）
            std::array<std::uint8_t, 2> Head{};
            if (co_await ReadExact(std::span<std::uint8_t>(Head)))
            {
                co_return std::pair{Error::IoError, Request{}};
            }
            if (Head[0] != Version)
            {
                co_return std::pair{Error::VersionMismatch, Request{}};
            }
            std::vector<std::uint8_t> Methods(Head[1]);
            if (!Methods.empty() && co_await ReadExact(Methods))
            {
                co_return std::pair{Error::IoError, Request{}};
            }

            // 2. 选择认证方法（检查客户端方法列表）
            std::uint8_t SelectedMethod;
            if (EnableAuth)
            {
                SelectedMethod = static_cast<std::uint8_t>(AuthMethod::UserPass);
            }
            else
            {
                SelectedMethod = static_cast<std::uint8_t>(AuthMethod::NoAuth);
            }
            const bool Acceptable =
                std::find(Methods.begin(), Methods.end(), SelectedMethod) != Methods.end();
            if (!Acceptable)
            {
                const auto ReplyError =
                    co_await SendMethodReply(static_cast<std::uint8_t>(AuthMethod::NoAcceptable));
                if (ReplyError != Error::None)
                {
                    co_return std::pair{ReplyError, Request{}};
                }
                co_return std::pair{Error::NotSupported, Request{}};
            }

            // 3. 发送方法选择
            if (co_await SendMethodReply(SelectedMethod) != Error::None)
            {
                co_return std::pair{Error::IoError, Request{}};
            }

            // 4. 认证（如需）
            if (SelectedMethod == static_cast<std::uint8_t>(AuthMethod::UserPass))
            {
                const auto AuthenticationError =
                    co_await UserpassAuth(Username, Password, Config.ResolveAuthenticator());
                if (AuthenticationError != Error::None)
                {
                    co_return std::pair{AuthenticationError, Request{}};
                }
            }

            // 5. 解析请求
            Request RequestValue;
            const auto RequestError = co_await ReadRequest(RequestValue);
            if (RequestError != Error::None)
            {
                co_await SendReply(ReplyCode::GeneralFailure);
                co_return std::pair{RequestError, Request{}};
            }

            // 6. 命令检查
            if (RequestValue.Cmd == Command::Connect && !EnableTcp)
            {
                co_await SendReply(ReplyCode::CommandNotSupported);
                co_return std::pair{Error::NotSupported, Request{}};
            }
            if (RequestValue.Cmd == Command::UdpAssociate && !EnableUdp)
            {
                co_await SendReply(ReplyCode::CommandNotSupported);
                co_return std::pair{Error::NotSupported, Request{}};
            }

            // 7. CONNECT 应答（默认立即发送；defer 时由调用方拨号后发送）
            if (!Config.DeferConnectReply)
            {
                const auto ReplyError = co_await SendReply(ReplyCode::Success);
                if (ReplyError != Error::None)
                {
                    co_return std::pair{ReplyError, Request{}};
                }
            }
            Req_ = RequestValue;
            Handshaken_ = true;
            co_return std::pair{Error::None, std::move(RequestValue)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const Request &
        {
            return Req_;
        }

        /**
         * @brief 获取客户端握手返回的绑定地址（UDP_ASSOCIATE 的 BND）
         * @return 绑定地址（握手前为空）
         */
        [[nodiscard]] auto BindEndpoint() const -> const Address &
        {
            return Bind_;
        }

        /**
         * @brief 转移协议认证产生的账户租约
         * @return 已认证账户租约；无认证或静态认证时为空
         */
        [[nodiscard]] auto TakeAuthLease() -> std::optional<Preview::Account::Lease>
        {
            return std::move(AuthLease_);
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

        /**
         * @brief 发送 CONNECT 应答（延迟握手由调用方拨号后发送）
         * @param Code 响应码
         * @return 发送错误码
         */
        [[nodiscard]] auto SendConnectReply(ReplyCode Code) const
            -> Net::awaitable<Error>
        {
            co_return co_await SendReply(Code);
        }

        /**
         * @brief 发送带 BND 地址的应答（UDP_ASSOCIATE 用）
         * @param Code 响应码
         * @param Bind BND 地址（空 = 0.0.0.0:0）
         * @return 发送错误码
         */
        [[nodiscard]] auto SendAssocReply(
            ReplyCode Code,
            const Address &Bind) const -> Net::awaitable<Error>
        {
            co_return co_await SendReply(Code, Bind);
        }

    private:
        /**
         * @brief 发送方法选择回复
         */
        [[nodiscard]] auto SendMethodReply(std::uint8_t Method) const -> Net::awaitable<Error>
        {
            const std::array<std::uint8_t, 2> Wire{Version, Method};
            if (co_await SendBytes(Wire))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief RFC 1929 用户名/密码认证（服务端）
         * @param Username 期望用户名
         * @param Password 期望密码
         * @param Auth 认证器（nullptr = 静态比对）
         * @return 错误码；凭据失败为 BadAuth，底层读写失败为 IoError
         */
        [[nodiscard]] auto UserpassAuth(
            const std::string &Username,
            const std::string &Password,
            const Preview::Authenticator *Auth) -> Net::awaitable<Error>
        {
            std::array<std::uint8_t, 2> Head{};
            if (co_await ReadExact(std::span<std::uint8_t>(Head)))
            {
                co_return Error::IoError;
            }
            if (Head[0] != 0x01)
            {
                co_return Error::BadAuth;
            }
            std::vector<std::uint8_t> UserBytes(Head[1]);
            if (co_await ReadExact(UserBytes))
            {
                co_return Error::IoError;
            }
            std::array<std::uint8_t, 1> PasswordLength{};
            if (co_await ReadExact(std::span<std::uint8_t>(PasswordLength)))
            {
                co_return Error::IoError;
            }
            std::vector<std::uint8_t> PasswordBytes(PasswordLength[0]);
            if (co_await ReadExact(PasswordBytes))
            {
                co_return Error::IoError;
            }
            const std::string UserValue(UserBytes.begin(), UserBytes.end());
            const std::string PasswordValue(PasswordBytes.begin(), PasswordBytes.end());
            bool Authenticated;
            if (Auth)
            {
                auto AuthenticationResult = Auth->Check(UserValue, PasswordValue);
                Authenticated = AuthenticationResult.Ok;
                if (Authenticated && AuthenticationResult.Lease)
                {
                    AuthLease_ = std::move(AuthenticationResult.Lease);
                }
            }
            else
            {
                const auto UserMatches = Preview::ConstantTimeEqual(UserValue, Username);
                const auto PasswordMatches = Preview::ConstantTimeEqual(PasswordValue, Password);
                Authenticated = UserMatches && PasswordMatches;
            }
            std::uint8_t Status;
            if (Authenticated)
            {
                Status = std::uint8_t{0x00};
            }
            else
            {
                Status = std::uint8_t{0x01};
            }
            const std::array<std::uint8_t, 2> Response{0x01, Status};
            if (co_await SendBytes(Response))
            {
                co_return Error::IoError;
            }
            if (!Authenticated)
            {
                co_return Error::BadAuth;
            }
            co_return Error::None;
        }

        /**
         * @brief 发送响应（Bind 空 = 0.0.0.0:0）
         */
        [[nodiscard]] auto SendReply(ReplyCode Code, const Address &Bind = {}) const
            -> Net::awaitable<Error>
        {
            Reply ReplyValue;
            ReplyValue.Ver = Version;
            ReplyValue.Code = Code;
            if (Bind.Host.empty())
            {
                ReplyValue.Bind.Type = AddressType::Ipv4;
                ReplyValue.Bind.Host = "0.0.0.0";
                ReplyValue.Bind.Port = 0;
            }
            else
            {
                ReplyValue.Bind = Bind;
            }
            BuildReply(ReplyValue, TxWire_);
            if (TxWire_.empty())
            {
                co_return Error::BadAddress;
            }
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 读取并解析请求（命令 + 地址）
         */
        [[nodiscard]] auto ReadRequest(Request &Output) -> Net::awaitable<Error>
        {
            std::array<std::uint8_t, 4> Head{};
            const auto ErrorCode = co_await ReadExact(std::span<std::uint8_t>(Head));
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (Head[0] != Version)
            {
                co_return Error::VersionMismatch;
            }
            Output.Cmd = static_cast<Command>(Head[1]);
            if (Output.Cmd != Command::Connect && Output.Cmd != Command::UdpAssociate)
            {
                co_return Error::NotSupported;
            }
            if (Head[2] != 0)
            {
                co_return Error::BadMessage;
            }
            Output.Target.Type = static_cast<AddressType>(Head[3]);
            co_return co_await ReadAddress(Output.Target);
        }

        /**
         * @brief 读取响应（Reply）
         */
        [[nodiscard]] auto ReadReply(Reply &Output) -> Net::awaitable<Error>
        {
            std::array<std::uint8_t, 4> Head{};
            if (co_await ReadExact(std::span<std::uint8_t>(Head)))
            {
                co_return Error::IoError;
            }
            if (Head[0] != Version)
            {
                co_return Error::VersionMismatch;
            }
            if (Head[2] != 0)
            {
                co_return Error::BadMessage;
            }
            Output.Code = static_cast<ReplyCode>(Head[1]);
            Output.Bind.Type = static_cast<AddressType>(Head[3]);
            co_return co_await ReadAddress(Output.Bind);
        }

        /**
         * @brief 读取地址（ATYP + ADDR + PORT）
         * @details 地址体委托统一实现（见 Protocol/common::ReadAddressBody），
         *          端口（2B BE）本地读取。
         */
        [[nodiscard]] auto ReadAddress(Address &Output) -> Net::awaitable<Error>
        {
            const auto ErrorCode = co_await Preview::Protocol::Common::ReadAddressBody(
                Output,
                [this](std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
                {
                    return ReadExactImpl(Buffer);
                });
            if (ErrorCode != Error::None)
            {
                co_return ErrorCode;
            }
            if (Output.Type == AddressType::Domain && Output.Host.empty())
            {
                co_return Error::BadMessage;
            }
            std::array<std::uint8_t, 2> Port{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(Port)))
            {
                co_return Error::IoError;
            }
            Output.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];
            co_return Error::None;
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

        SharedTransmission NextLayer_; ///< 上游传输（独占所有权）
        Request Req_;                    ///< 服务端握手解析结果
        Address Bind_;                   ///< 客户端握手 BND 地址
        std::optional<Preview::Account::Lease> AuthLease_{}; ///< 协议认证租约
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> Buf_{Mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t Used_{0};            ///< 缓冲中有效字节数
        bool Handshaken_{false};         ///< 握手完成标志
        /// 发送缓冲（Arena 复用，热路径零分配）；mutable：const 握手方法内可写
        mutable typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()};
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Socks5
