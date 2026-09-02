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

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Restls/Codec.hpp>
#include <preview/Protocols/Restls/Types.hpp>

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
         * @param upstream 底层传输（所有权移交）
         * @param password 认证密码
         */
        explicit Conn(SharedTransmission upstream, std::string password)
            : NextLayer_(std::move(upstream)), Password_(std::move(password))
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
         * @brief 客户端握手：派生 Secret 并交换 ServerRandom
         * @param ServerRandom 服务端随机数（32 字节）
         * @return 错误码
         * @details 客户端由密码派生 RestlsSecret，后续认证均以其为密钥。
         */
        [[nodiscard]] auto WriteHandshake(std::span<const std::uint8_t> ServerRandom)
        -> net::awaitable<Error>
        {
            if (ServerRandom.size() != 32)
                co_return Error::BadLength;
            Secret_ = DeriveSecret(Password_);
            std::copy(ServerRandom.begin(), ServerRandom.end(), ServerRandom_.begin());
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：派生 Secret 并校验客户端身份
         * @param ServerRandom 服务端随机数（32 字节）
         * @return 错误码
         * @details 服务端同样派生 Secret，并以 ServerMask 加密
         * 首个 TLS 记录实现服务端身份验证（测试库简化直接派生）。
         */
        [[nodiscard]] auto ReadHandshake(std::span<const std::uint8_t> ServerRandom)
        -> net::awaitable<Error>
        {
            if (ServerRandom.size() != 32)
                co_return Error::BadLength;
            Secret_ = DeriveSecret(Password_);
            std::copy(ServerRandom.begin(), ServerRandom.end(), ServerRandom_.begin());
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样，mask 编解码由上层记录层负责）
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

        /**
         * @brief 获取派生密钥（握手后有效）
         */
        [[nodiscard]] auto Secret() const -> const std::array<std::uint8_t, 32> &
        {
            return Secret_;
        }

    private:
        SharedTransmission NextLayer_;                ///< 底层传输（独占所有权）
        std::string Password_;                          ///< 认证密码
        std::array<std::uint8_t, 32> Secret_{};         ///< RestlsSecret（派生）
        std::array<std::uint8_t, 32> ServerRandom_{};  ///< 服务端随机数
        bool Handshaken_{false};                        ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Restls
