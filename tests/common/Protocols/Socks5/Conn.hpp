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

#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Protocol/Address.hpp>

#include <common/Core/Authenticator.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Socks5/Codec.hpp>
#include <common/Protocols/Socks5/Types.hpp>

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
        explicit Conn(SharedTransmission upstream) : next_layer_(std::move(upstream))
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return next_layer_->Executor();
        }

        /**
         * @brief 异步读取（预读缓冲优先）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         * @details 握手阶段预读的剩余字节先被消费，清空后透传底层。
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            if (used_ > 0)
            {
                const auto n = std::min(Buffer.size(), used_);
                std::memcpy(Buffer.data(), buf_.data(), n);
                if (n < used_)
                {
                    std::memmove(buf_.data(), buf_.data() + n, used_ - n);
                }
                else
                {
                    buf_.clear();
                }
                used_ -= n;
                co_return n;
            }
            co_return co_await next_layer_->AsyncReadSome(Buffer, ec);
        }

        /**
         * @brief 异步写入（透传）
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->AsyncWriteSome(Buffer, ec);
        }

        /**
         * @brief 关闭传输层
         */
        void Close() override
        {
            if (next_layer_)
            {
                next_layer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            if (next_layer_)
            {
                next_layer_->Cancel();
            }
        }

        /**
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return next_layer_ != nullptr && handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return next_layer_;
        }

        /**
         * @brief 获取底层传输引用（const 版本）
         * @return 底层传输
         */
        [[nodiscard]] auto Underlying() const noexcept -> SharedTransmission
        {
            return next_layer_;
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(next_layer_);
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
                g.methods = std::vector<std::uint8_t>{static_cast<std::uint8_t>(AuthMethod::user_pass)};
            }
            else
            {
                g.methods = std::vector<std::uint8_t>{static_cast<std::uint8_t>(AuthMethod::no_auth)};
            }
                        BuildGreeting(g, TxWire_);
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::io_error;
            }

            // 2. 读取方法选择
            std::array<std::uint8_t, 2> sel{};
            if (co_await ReadExact(std::span<std::uint8_t>(sel)))
            {
                co_return Error::io_error;
            }
            if (sel[0] != Version)
            {
                co_return Error::version_mismatch;
            }
            if (sel[1] == static_cast<std::uint8_t>(AuthMethod::no_acceptable))
            {
                co_return Error::not_supported;
            }

            // 3. 认证（如需，RFC 1929）
            if (sel[1] == static_cast<std::uint8_t>(AuthMethod::user_pass))
            {
                BuildUserpass(username, password, TxWire_);
                if (co_await SendBytes(TxWire_))
                {
                    co_return Error::io_error;
                }
                std::array<std::uint8_t, 2> resp{};
                if (co_await ReadExact(std::span<std::uint8_t>(resp)))
                {
                    co_return Error::io_error;
                }
                if (resp[0] != 0x01 || resp[1] != 0x00)
                {
                    co_return Error::bad_auth;
                }
            }
            else if (sel[1] != static_cast<std::uint8_t>(AuthMethod::no_auth) && !EnableAuth)
            {
                co_return Error::not_supported;
            }

            // 4. 发送请求
                        BuildRequest(req, TxWire_);
            if (co_await SendBytes(TxWire_))
            {
                co_return Error::io_error;
            }

            // 5. 读取响应并校验
            Reply rep;
            auto err = co_await ReadReply(rep);
            if (err != Error::none)
            {
                co_return err;
            }
            if (rep.Code != ReplyCode::success)
            {
                co_return Error::bad_auth;
            }
            bind_ = rep.Bind;
            handshaken_ = true;
            co_return Error::none;
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
                co_return std::pair{Error::io_error, Request{}};
            }
            if (head[0] != Version)
            {
                co_return std::pair{Error::version_mismatch, Request{}};
            }
            std::vector<std::uint8_t> methods(head[1]);
            if (!methods.empty() && co_await ReadExact(methods))
            {
                co_return std::pair{Error::io_error, Request{}};
            }

            // 2. 选择认证方法（检查客户端方法列表）
            std::uint8_t Want;
            if (EnableAuth)
            {
                Want = static_cast<std::uint8_t>(AuthMethod::user_pass);
            }
            else
            {
                Want = static_cast<std::uint8_t>(AuthMethod::no_auth);
            }
            const bool acceptable = std::find(methods.begin(), methods.end(), Want) != methods.end();
            if (!acceptable)
            {
                co_await SendMethodReply(static_cast<std::uint8_t>(AuthMethod::no_acceptable));
                co_return std::pair{Error::not_supported, Request{}};
            }

            // 3. 发送方法选择
            if (co_await SendMethodReply(Want) != Error::none)
            {
                co_return std::pair{Error::io_error, Request{}};
            }

            // 4. 认证（如需）
            if (Want == static_cast<std::uint8_t>(AuthMethod::user_pass))
            {
                const bool Ok = co_await UserpassAuth(username, password, cfg.Authenticator);
                if (!Ok)
                {
                    co_return std::pair{Error::bad_auth, Request{}};
                }
            }

            // 5. 解析请求
            Request req;
            auto err = co_await ReadRequest(req);
            if (err != Error::none)
            {
                co_await SendReply(ReplyCode::general_failure);
                co_return std::pair{err, Request{}};
            }

            // 6. 命令检查
            if (req.Cmd == Command::Connect && !EnableTcp)
            {
                co_await SendReply(ReplyCode::command_not_supported);
                co_return std::pair{Error::not_supported, Request{}};
            }
            if (req.Cmd == Command::UdpAssociate && !EnableUdp)
            {
                co_await SendReply(ReplyCode::command_not_supported);
                co_return std::pair{Error::not_supported, Request{}};
            }

            // 7. CONNECT 应答（默认立即发送；defer 时由调用方拨号后发送）
            if (!cfg.DeferConnectReply)
            {
                co_await SendReply(ReplyCode::success);
            }
            req_ = req;
            handshaken_ = true;
            co_return std::pair{Error::none, std::move(req)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const Request &
        {
            return req_;
        }

        /**
         * @brief 获取客户端握手返回的绑定地址（UDP_ASSOCIATE 的 BND）
         * @return 绑定地址（握手前为空）
         */
        [[nodiscard]] auto BindEndpoint() const -> const Address &
        {
            return bind_;
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
                co_return Error::io_error;
            }
            co_return Error::none;
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
            const std::string user_str(user.begin(), user.end());
            const std::string pass_str(pass.begin(), pass.end());
            bool Ok;
            if (Auth)
            {
                Ok = Auth->Check(user_str, pass_str).Ok;
            }
            else
            {
                Ok = (user_str == username && pass_str == password);
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
                co_return Error::io_error;
            }
            co_return Error::none;
        }

        /**
         * @brief 读取并解析请求（命令 + 地址）
         */
        [[nodiscard]] auto ReadRequest(Request &req) -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 4> head{};
            auto ec = co_await ReadExact(std::span<std::uint8_t>(head));
            if (ec)
            {
                co_return Error::io_error;
            }
            if (head[0] != Version)
            {
                co_return Error::version_mismatch;
            }
            req.Cmd = static_cast<Command>(head[1]);
            if (req.Cmd != Command::Connect && req.Cmd != Command::UdpAssociate)
            {
                co_return Error::not_supported;
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
                co_return Error::io_error;
            }
            if (head[0] != Version)
            {
                co_return Error::version_mismatch;
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
            auto err = co_await Preview::Protocol::Common::ReadAddressBody(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return ReadExactImpl(dst); });
            if (err != Error::none)
            {
                co_return err;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(port)))
            {
                co_return Error::io_error;
            }
            addr.Port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];
            co_return Error::none;
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
                if (used_ > 0)
                {
                    const auto n = std::min(dst.size() - Done, used_);
                    std::memcpy(dst.data() + Done, buf_.data(), n);
                    if (n < used_)
                    {
                        std::memmove(buf_.data(), buf_.data() + n, used_ - n);
                        used_ -= n;
                    }
                    else
                    {
                        buf_.clear();
                        used_ = 0;
                    }
                    Done += n;
                    continue;
                }
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncReadSome(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || n == 0)
                {
                    co_return true;
                }
                buf_.insert(buf_.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
                used_ += n;
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
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncWriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data() + Done),
                                               Data.size() - Done),
                    ec);
                if (ec)
                {
                    co_return true;
                }
                Done += n;
            }
            co_return false;
        }

        SharedTransmission next_layer_; ///< 上游传输（独占所有权）
        Request req_;                    ///< 服务端握手解析结果
        Address bind_;                   ///< 客户端握手 BND 地址
        Memory mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename std::template Buffer<std::uint8_t> buf_{mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t used_{0};            ///< 缓冲中有效字节数
        bool handshaken_{false};         ///< 握手完成标志
        /// 发送缓冲（Arena 复用，热路径零分配）；mutable：const 握手方法内可写
        mutable typename std::template Buffer<std::uint8_t> TxWire_{mem_.Arena()};
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Socks5
