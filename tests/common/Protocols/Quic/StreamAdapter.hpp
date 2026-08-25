/**
 * @file StreamAdapter.hpp
 * @brief QUIC 流传输适配器（接口骨架）
 * @details 将 QUIC 流（ngtcp2/nghttp3 上层）适配为统一的
 * Transmission 抽象。设计目标：
 * 1. 测试库不直接依赖 ngtcp2 —— 通过 StreamProvider 接口注入
 * 2. 生产者（QUIC 服务器）实现 StreamProvider，适配器包装为
 *    Transmission 供协议层（hysteria2/tuic handler）使用
 * 3. 与生产库 net/transport/quic/Server.hpp 的 Quic::Stream 对应，
 *    后续可直接替换为生产实现
 * @note 本文件仅定义接口契约，不包含 ngtcp2 具体实现。
 *       完整 ngtcp2 封装见生产库 net/transport/quic/Server.hpp。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <system_error>

#include <common/Core/Transmission.hpp>

namespace Preview::Quic
{

    namespace net = boost::asio;

    /**
     * @class StreamProvider
     * @brief QUIC 流提供者（生产者接口）
     * @details 由底层 QUIC 会话实现：提供流级读写、流 ID 查询、
     * 打开新流、单流关闭。测试可注入内存实现（无 ngtcp2 依赖）。
     */
    class StreamProvider
    {
    public:
        virtual ~StreamProvider() = default;

        /**
         * @brief 异步读取流数据
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出
         * @return 实际读取字节数
         */
        [[nodiscard]] virtual auto Read(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 异步写入流数据
         * @param Buffer 待写数据
         * @param ec 错误码输出
         * @return 实际写入字节数
         */
        [[nodiscard]] virtual auto Write(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 关闭流（发送 FIN）
         */
        virtual void Close() = 0;

        /**
         * @brief 获取流 ID
         * @return 流标识符
         */
        [[nodiscard]] virtual auto StreamId() const noexcept -> std::int64_t = 0;

        /**
         * @brief 流是否已关闭
         * @return 关闭返回 true
         */
        [[nodiscard]] virtual auto IsClosed() const noexcept -> bool = 0;
    };

    /// 流提供者共享指针
    using SharedStreamProvider = std::shared_ptr<StreamProvider>;

    /**
     * @class StreamAdapter
     * @brief 将 StreamProvider 适配为 Transmission
     * @details 持有提供者的独占所有权，对外暴露 Transmission 接口。
     * 协议层（hysteria2/tuic）通过本适配器把 QUIC 流当作普通
     * 字节流处理，屏蔽 QUIC 细节。
     */
    class StreamAdapter final : public Transmission
    {
    public:
        /**
         * @brief 构造函数
         * @param ex 执行器
         * @param provider 流提供者（所有权移交）
         */
        StreamAdapter(net::any_io_executor ex, SharedStreamProvider provider)
            : ex_(std::move(ex)), provider_(std::move(provider))
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return ex_;
        }

        /**
         * @brief 异步读取（委托提供者）
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!provider_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await provider_->Read(Buffer, ec);
        }

        /**
         * @brief 异步写入（委托提供者）
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!provider_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await provider_->Write(Buffer, ec);
        }

        /**
         * @brief 关闭流
         */
        void Close() override
        {
            if (provider_)
            {
                provider_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
        }

        /**
         * @brief 传输类型：可靠流（QUIC 流语义等同 TCP）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

    private:
        net::any_io_executor ex_;           ///< 执行器
        SharedStreamProvider provider_;   ///< 流提供者（独占所有权）
    };

    /// 适配器共享指针
    using SharedStreamAdapter = std::shared_ptr<StreamAdapter>;

} // namespace Preview::Quic
