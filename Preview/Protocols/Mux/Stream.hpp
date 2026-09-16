/**
 * @file Stream.hpp
 * @brief 多路复用流传输适配器（StreamHandle → Transmission）
 * @details 包装 mux 虚拟流句柄，将其暴露为新传输接口，作为上层协议
 * Server/Client（vless/trojan/socks5/...）的挂载点。流无底层链，
 * NextLayer() 返回 nullptr（叶子节点）。
 * @note StreamHandle::Close() / Reset() 为协程，适配器经 co_spawn
 *       投递到句柄 executor，并以 shared_ptr 捕获句柄保活。
 * @note 读返回 0 时视为对端关闭，ErrorCode 置为 Error::UnexpectedEof。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Mux/Session.hpp>

namespace Preview::Mux
{

    /**
     * @class StreamTransmission
     * @brief 流传输适配器（StreamHandle → Transmission）
     * @details 将 mux 虚拟流句柄包装为 Transmission 接口，供上层协议
     * 会话直接挂载（装饰器链叶子节点）。
     */
    class StreamTransmission : public Transmission
    {
    public:
        /**
         * @brief 构造
         * @param Handle mux 虚拟流句柄（所有权移交）
         */
        explicit StreamTransmission(std::shared_ptr<StreamHandle<>> Handle)
            : Handle_(std::move(Handle))
        {
        }

        /**
         * @brief 获取执行器
         * @return 流执行器（句柄为空时返回默认执行器）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (Handle_)
            {
                return Handle_->Executor();
            }
            return Net::any_io_executor{};
        }

        /**
         * @brief 异步读取部分数据
         * @param Buffer 接收缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 实际读取字节数
         * @details 转调 StreamHandle::ReadSome；返回 0（对端关闭、半关或超时）
         *          时 ErrorCode 置为 Error::UnexpectedEof。
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!Handle_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            const auto N = co_await Handle_->ReadSome(AsU8(Buffer));
            if (N == 0)
            {
                ErrorCode = make_error_code(Error::UnexpectedEof);
            }
            else
            {
                ErrorCode.clear();
            }
            co_return N;
        }

        /**
         * @brief 异步写入部分数据
         * @param Buffer 待写数据
         * @param ErrorCode 错误码输出参数
         * @return 实际写入字节数
         * @details 转调 StreamHandle::WriteAll（内部完整写入），
         *          错误经 boost→std 隐式转换存入 ErrorCode。
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!Handle_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            const auto Err = co_await Handle_->WriteAll(AsU8(Buffer));
            if (Err)
            {
                ErrorCode = Err;
                co_return 0;
            }
            ErrorCode.clear();
            co_return Buffer.size();
        }

        /**
         * @brief 关闭流
         * @details StreamHandle::Close() 是协程，经 co_spawn 投递到
         * 流执行器上执行；lambda 按值捕获句柄保证存活。
         */
        auto Close() -> void override
        {
            auto Handle = Handle_;
            if (!Handle)
            {
                return;
            }
            Net::co_spawn(
                Handle->Executor(),
                [Handle]() -> Net::awaitable<void> { co_await Handle->Close(); },
                Net::detached);
        }

        /**
         * @brief 重置流（发 RST，对端读返回 0）
         * @details 与 Close() 同样经 co_spawn 投递执行；区别是向对端
         * 发送重置帧，对端挂起读被唤醒并返回 0。
         */
        auto Reset() -> void
        {
            auto Handle = Handle_;
            if (!Handle)
            {
                return;
            }
            Net::co_spawn(
                Handle->Executor(),
                [Handle]() -> Net::awaitable<void> { co_await Handle->Reset(); },
                Net::detached);
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            auto Handle = Handle_;
            if (Handle)
            {
                Net::dispatch(
                    Handle->Executor(), [Handle]() { Handle->Cancel(); });
            }
        }

        /**
         * @brief 流是否打开
         * @return true = 句柄存活且未关闭
         */
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return Handle_ && Handle_->IsOpen();
        }

        /**
         * @brief 获取底层流句柄
         * @return mux 虚拟流句柄
         */
        [[nodiscard]] auto Handle() const noexcept -> std::shared_ptr<StreamHandle<>>
        {
            return Handle_;
        }

    private:
        std::shared_ptr<StreamHandle<>> Handle_; ///< mux 虚拟流句柄
    };

    /// 流传输共享指针
    using SharedStream = std::shared_ptr<StreamTransmission>;

} // namespace Preview::Mux
