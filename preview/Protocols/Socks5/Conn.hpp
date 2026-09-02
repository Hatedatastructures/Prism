/**
 * @file Conn.hpp
 * @brief SOCKS5 流连接对象（TCP，实现 Transmission）
 * @details 单条 SOCKS5 连接的完整协议状态：
 * - 客户端握手：WriteHandshake(req)（Greeting → 方法选择 → 认证 →
 *   请求 → 响应校验），成功后 BindEndpoint() 可取 BND 地址
 * - 服务端握手：ReadHandshake(cfg)（Greeting → 方法协商 → 认证 →
 *   请求解析 → 响应），返回解析的请求
 * 握手后为纯字节流透传（预读缓冲优先）。UDP 数据面由 Dgram.hpp
 * 提供（独立包连接类型，嵌入本连接）。
 * @note 对齐 mihomo transport：TCP = net.Conn（纯流语义）。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
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
         * @param upstream 上游传输（所有权移交）
         */
        explicit Conn(SharedTransmission upstream) : NextLayer_(std::move(upstream))
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 异步读取（预读缓冲优先）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         * @details 握手阶段预读的剩余字节先被消费，清空后透传底层。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            Ec.clear();
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
            co_return co_await NextLayer_->async_read_some(Buffer, Ec);
        }

        /**
         * @brief 异步写入（透传）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_write_some(Buffer, Ec);
        }

        /**
         * @brief 关闭传输层
         */
        void Close() override
        {
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
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
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        /**
         * @brief 获取底层传输引用（const 版本）
         * @return 底层传输
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
         * @param req 目标请求（cmd + Target）
         * @param EnableAuth 是否启用用户名/密码认证（RFC 1929）
         * @param username 认证用户名（EnableAuth 为 true 时生效）
         * @param password 认证密码（EnableAuth 为 true 时生效）
         * @return 错误码
         * @details 完整客户端流程（RFC 1928 + 1929）。成功后 BND
         * 地址可通过 BindEndpoint() 获取（UDP_ASSOCIATE 用）。
         */
        [[nodiscard]] auto WriteHandshake(const Request &req, const ClientConfig &cfg)
            -> net::awaitable<Error>
        {
            const auto &EnableAuth = cfg.EnableAuth;
            const auto &username = cfg.username;
            const auto &password = cfg.password;
            // 1. 发送 Greeting
            Greeting g;
            g.Ver = Version;
            if (EnableAuth)
            {
                g.Methods = std::vector<std::uint8_t>{static_cast<std::uint8_t>(AuthMethod::UserPass)};
            }
            else
            {
                g.Methods = std::vector<std::uint8_t>{static_cast<std::uint8_t>(AuthMethod::NoAuth)};
            }
                BuildGreeting(g, TxWire_);
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::IoError;
            }

            // 2. 读取方法选择
            std::array<std::uint8_t, 2> sel{};
            if (co_await ReadExact(std::span<std::uint8_t>(sel)))
            {
                co_return Error::IoError;
            }
            if (sel[0] != Version)
            {
                co_return Error::VersionMismatch;
            }
            if (sel[1] == static_cast<std::uint8_t>(AuthMethod::NoAcceptable))
            {
                co_return Error::NotSupported;
            }

            // 3. 认证（如需，RFC 1929）
            if (sel[1] == static_cast<std::uint8_t>(AuthMethod::UserPass))
            {
                BuildUserpass(username, password, TxWire_);
                if (co_await SendBytes(TxWire_))
                {
                    co_return Error::IoError;
                }
                std::array<std::uint8_t, 2> resp{};
                if (co_await ReadExact(std::span<std::uint8_t>(resp)))
                {
                    co_return Error::IoError;
                }
                if (resp[0] != 0x01 || resp[1] != 0x00)
                {
                    co_return Error::BadAuth;
                }
            }
            else if (sel[1] != static_cast<std::uint8_t>(AuthMethod::NoAuth) && !EnableAuth)
            {
                co_return Error::NotSupported;
            }

            // 4. 发送请求
            BuildRequest(req, TxWire_);
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::IoError;
            }

            // 5. 读取响应并校验
            Reply rep;
            auto Err = co_await ReadReply(rep);
            if (Err != Error::None)
            {
                co_return Err;
            }
            if (rep.Code != ReplyCode::Success)
            {
                co_return Error::BadAuth;
            }
            Bind_ = rep.Bind;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：Greeting → 方法协商 → 认证 → 请求 → 响应
         * @param EnableTcp 是否允许 CONNECT 命令（TCP 转发）
         * @param EnableUdp 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
         * @param EnableAuth 是否启用用户名/密码认证（RFC 1929）
         * @param username 认证用户名（EnableAuth 为 true 时生效）
         * @param password 认证密码（EnableAuth 为 true 时生效）
         * @return 错误码与解析的请求
         * @details 完整服务端流程（RFC 1928 + 1929）。失败时按协议
         * 发送对应错误响应。
         */
        [[nodiscard]] auto ReadHandshake(const ServerConfig &cfg)
            -> net::awaitable<std::pair<Error, Request>>
        {
            const auto &EnableTcp = cfg.EnableTcp;
            const auto &EnableUdp = cfg.EnableUdp;
            const auto &EnableAuth = cfg.EnableAuth;
            const auto &username = cfg.username;
            const auto &password = cfg.password;
            // 1. 方法协商：读取 Greeting（2B 头 + 方法列表）
            std::array<std::uint8_t, 2> head{};
            if (co_await ReadExact(std::span<std::uint8_t>(head)))
            {
                co_return std::pair{Error::IoError, Request{}};
            }
            if (head[0] != Version)
            {
                co_return std::pair{Error::VersionMismatch, Request{}};
            }
            std::vector<std::uint8_t> Methods(head[1]);
            if (!Methods.empty() && co_await ReadExact(Methods))
            {
                co_return std::pair{Error::IoError, Request{}};
            }

            // 2. 选择认证方法（检查客户端方法列表）
            std::uint8_t Want;
            if (EnableAuth)
            {
                Want = static_cast<std::uint8_t>(AuthMethod::UserPass);
            }
            else
            {
                Want = static_cast<std::uint8_t>(AuthMethod::NoAuth);
            }
            const bool Acceptable = std::find(Methods.begin(), Methods.end(), Want) != Methods.end();
            if (!Acceptable)
            {
                co_await SendMethodReply(static_cast<std::uint8_t>(AuthMethod::NoAcceptable));
                co_return std::pair{Error::NotSupported, Request{}};
            }

            // 3. 发送方法选择
            if (co_await SendMethodReply(Want) != Error::None)
            {
                co_return std::pair{Error::IoError, Request{}};
            }

            // 4. 认证（如需）
            if (Want == static_cast<std::uint8_t>(AuthMethod::UserPass))
            {
                const bool Ok = co_await UserpassAuth(username, password, cfg.Authenticator);
                if (!Ok)
                {
                    co_return std::pair{Error::BadAuth, Request{}};
                }
            }

            // 5. 解析请求
            Request req;
            auto Err = co_await ReadRequest(req);
            if (Err != Error::None)
            {
                co_await SendReply(ReplyCode::GeneralFailure);
                co_return std::pair{Err, Request{}};
            }

            // 6. 命令检查
            if (req.Cmd == Command::Connect && !EnableTcp)
            {
                co_await SendReply(ReplyCode::CommandNotSupported);
                co_return std::pair{Error::NotSupported, Request{}};
            }
            if (req.Cmd == Command::UdpAssociate && !EnableUdp)
            {
                co_await SendReply(ReplyCode::CommandNotSupported);
                co_return std::pair{Error::NotSupported, Request{}};
            }

            // 7. CONNECT 应答（默认立即发送；defer 时由调用方拨号后发送）
            if (!cfg.DeferConnectReply)
            {
                co_await SendReply(ReplyCode::Success);
            }
            Req_ = req;
            Handshaken_ = true;
            co_return std::pair{Error::None, std::move(req)};
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
         * @brief 精确分段读取（供包连接复用预读缓冲）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> dst) 
            -> net::awaitable<bool>
        {
            return ReadExactImpl(dst);
        }

        /**
         * @brief 发送 CONNECT 应答（延迟握手由调用方拨号后发送）
         * @param Code 响应码
         * @return 发送错误码
         */
        [[nodiscard]] auto SendConnectReply(ReplyCode Code) const 
            -> net::awaitable<Error>
        {
            co_return co_await SendReply(Code);
        }

        /**
         * @brief 发送带 BND 地址的应答（UDP_ASSOCIATE 用）
         * @param Code 响应码
         * @param Bind BND 地址（空 = 0.0.0.0:0）
         * @return 发送错误码
         */
        [[nodiscard]] auto SendAssocReply(ReplyCode Code, const Address &Bind) const
            -> net::awaitable<Error>
        {
            co_return co_await SendReply(Code, Bind);
        }

    private:
        /**
         * @brief 发送方法选择回复
         */
        [[nodiscard]] auto SendMethodReply(std::uint8_t Method) const -> net::awaitable<Error>
        {
            const std::array<std::uint8_t, 2> wire{Version, Method};
            if (co_await SendBytes(wire))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief RFC 1929 用户名/密码认证（服务端）
         * @param username 期望用户名
         * @param password 期望密码
         * @param Auth 认证器（nullptr = 静态比对）
         * @return 认证结果
         */
        [[nodiscard]] auto UserpassAuth(const std::string &username, const std::string &password,
                                         const Preview::Authenticator *Auth) -> net::awaitable<bool>
        {
            std::array<std::uint8_t, 2> head{};
            if (co_await ReadExact(std::span<std::uint8_t>(head)))
            {
                co_return false;
            }
            if (head[0] != 0x01)
            {
                co_return false;
            }
            std::vector<std::uint8_t> user(head[1]);
            if (co_await ReadExact(user))
            {
                co_return false;
            }
            std::array<std::uint8_t, 1> plen{};
            if (co_await ReadExact(std::span<std::uint8_t>(plen)))
            {
                co_return false;
            }
            std::vector<std::uint8_t> pass(plen[0]);
            if (co_await ReadExact(pass))
            {
                co_return false;
            }
            const std::string UserStr(user.begin(), user.end());
            const std::string PassStr(pass.begin(), pass.end());
            bool Ok;
            if (Auth)
            {
                Ok = Auth->Check(UserStr, PassStr).Ok;
            }
            else
            {
                Ok = (UserStr == username && PassStr == password);
            }
            std::uint8_t status;
            if (Ok)
            {
                status = std::uint8_t{0x00};
            }
            else
            {
                status = std::uint8_t{0x01};
            }
            const std::array<std::uint8_t, 2> resp{0x01, status};
            co_await SendBytes(resp);
            co_return Ok;
        }

        /**
         * @brief 发送响应（Bind 空 = 0.0.0.0:0）
         */
        [[nodiscard]] auto SendReply(ReplyCode Code, const Address &Bind = {}) const
            -> net::awaitable<Error>
        {
            Reply rep;
            rep.Ver = Version;
            rep.Code = Code;
            if (Bind.Host.empty())
            {
                rep.Bind.Type = AddressType::Ipv4;
                rep.Bind.Host = "0.0.0.0";
                rep.Bind.Port = 0;
            }
            else
            {
                rep.Bind = Bind;
            }
            BuildReply(rep, TxWire_);
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 读取并解析请求（命令 + 地址）
         */
        [[nodiscard]] auto ReadRequest(Request &req) -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 4> head{};
            auto Ec = co_await ReadExact(std::span<std::uint8_t>(head));
            if (Ec)
            {
                co_return Error::IoError;
            }
            if (head[0] != Version)
            {
                co_return Error::VersionMismatch;
            }
            req.Cmd = static_cast<Command>(head[1]);
            if (req.Cmd != Command::Connect && req.Cmd != Command::UdpAssociate)
            {
                co_return Error::NotSupported;
            }
            req.Target.Type = static_cast<AddressType>(head[3]);
            co_return co_await ReadAddress(req.Target);
        }

        /**
         * @brief 读取响应（Reply）
         */
        [[nodiscard]] auto ReadReply(Reply &rep) -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 4> head{};
            if (co_await ReadExact(std::span<std::uint8_t>(head)))
            {
                co_return Error::IoError;
            }
            if (head[0] != Version)
            {
                co_return Error::VersionMismatch;
            }
            rep.Code = static_cast<ReplyCode>(head[1]);
            rep.Bind.Type = static_cast<AddressType>(head[3]);
            co_return co_await ReadAddress(rep.Bind);
        }

        /**
         * @brief 读取地址（ATYP + ADDR + PORT）
         * @details 地址体委托统一实现（见 Protocol/common::ReadAddressBody），
         *          端口（2B BE）本地读取。
         */
        [[nodiscard]] auto ReadAddress(Address &addr) -> net::awaitable<Error>
        {
            auto Err = co_await Preview::Protocol::Common::ReadAddressBody(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return ReadExactImpl(dst); });
            if (Err != Error::None)
            {
                co_return Err;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(port)))
            {
                co_return Error::IoError;
            }
            addr.Port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];
            co_return Error::None;
        }

        /**
         * @brief 精确读取指定字节数（内部缓冲优先 + 底层补充）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExactImpl(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < dst.size())
            {
                if (Used_ > 0)
                {
                    const auto N = std::min(dst.size() - Done, Used_);
                    std::memcpy(dst.data() + Done, Buf_.data(), N);
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
                std::array<std::uint8_t, 512> chunk{};
                std::error_code Ec;
                const auto N = co_await NextLayer_->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(chunk.data()), chunk.size()), Ec);
                if (Ec || N == 0)
                {
                    co_return true;
                }
                Buf_.insert(Buf_.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(N));
                Used_ += N;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code Ec;
                const auto N = co_await NextLayer_->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data() + Done),
                                               Data.size() - Done),
                    Ec);
                if (Ec)
                {
                    co_return true;
                }
                if (N == 0)
                {
                    co_return true; // 底层零字节写入，防死循环
                }
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_; ///< 上游传输（独占所有权）
        Request Req_;                    ///< 服务端握手解析结果
        Address Bind_;                   ///< 客户端握手 BND 地址
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
