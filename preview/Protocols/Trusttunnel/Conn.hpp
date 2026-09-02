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

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Trusttunnel/Codec.hpp>
#include <preview/Protocols/Trusttunnel/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
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
         * @param upstream 底层传输（所有权移交）
         * @param user 认证用户名
         * @param pass 认证密码
         */
        explicit Conn(SharedTransmission upstream, std::string user, std::string pass)
            : NextLayer_(std::move(upstream)), User_(std::move(user)), Pass_(std::move(pass))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发送 CONNECT 请求头
         * @param Target 目标主机
         * @param port 目标端口
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(std::string_view Target, std::uint16_t port)
        -> net::awaitable<Error>
        {
            const auto Auth = BasicAuth(User_, Pass_);
            std::string Header;
            Header.reserve(64 + Target.size() + Auth.size());
            Header += "CONNECT " + std::string(Target) + ":" + std::to_string(port) + " HTTP/2\r\n";
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
        [[nodiscard]] auto ReadHandshake(std::string &Target)
        -> net::awaitable<Error>
        {
            // 读取头块（简化：读到空行）
            std::array<std::uint8_t, 256> chunk{};
            std::string Header;
            bool FoundEnd = false;
            for (int I = 0; I < 16; ++I)
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || N == 0)
                    break;
                Header.append(reinterpret_cast<const char *>(chunk.data()), N);
                if (Header.find("\r\n\r\n") != std::string::npos)
                {
                    FoundEnd = true;
                    break;
                }
            }
            if (!FoundEnd)
                co_return Error::BadMagic;
            if (Header.find("CONNECT ") != 0)
                co_return Error::BadMagic;

            // 解析目标与认证
            const auto FirstLineEnd = Header.find("\r\n");
            const auto TargetLine = Header.substr(8, FirstLineEnd - 8);
            const auto Colon = TargetLine.find(':');
            if (Colon != std::string::npos)
                Target = TargetLine.substr(0, Colon);
            else
                Target = TargetLine;

            const auto AuthPos = Header.find("Proxy-Authorization: ");
            if (AuthPos == std::string::npos)
                co_return Error::BadAuth;
            const auto AuthStart = AuthPos + 21;
            const auto AuthEnd = Header.find("\r\n", AuthStart);
            const auto Auth = Header.substr(AuthStart, AuthEnd - AuthStart);
            if (!VerifyBasicAuth(Auth, User_, Pass_))
                co_return Error::BadAuth;

            Target_ = Target;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
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
            return std::move(NextLayer_);
        }

    private:
        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
        -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_write_some(AsBytes(Data.subspan(Done)), ec);
                if (ec || N == 0)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        std::string User_;                ///< 认证用户名
        std::string Pass_;                ///< 认证密码
        std::string Target_;              ///< CONNECT 目标（握手后）
        bool Handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Trusttunnel
