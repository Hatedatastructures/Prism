/**
 * @file PreviewMockTransport.hpp
 * @brief Preview 可编程传输桩
 * @details 供各协议 Dgram / Conn 错误路径测试复用，可编程行为：
 * - 注入读取字节流（ToRead，按需消费）
 * - 按调用次数注入读取错误（FailNextRead / ReadFailAt）
 * - 按调用次数注入写入错误（FailNextWrite / WriteFailAt）
 * - 限制单次写入返回长度（MaxWrite，模拟半包写）
 * - 捕获全部写入数据（Written）
 * - 空读通过外部执行器上的事件通知等待，不使用定时器轮询
 * - EofOnDrain 可将有限注入流显式标记为耗尽即 EOF
 * - Close()/Shutdown() 后读返回 0，写仅在 Close() 后失败
 * @note 仅测试代码使用，禁止被生产代码引用。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview
{

    namespace net = boost::asio;

    /**
     * @class PreviewMockTransport
     * @brief Preview 传输接口的可编程测试桩
     * @details 行为完全由测试方编排：读取从注入队列顺序消费，
     * 队列为空时默认等待下一次事件通知；设置 EofOnDrain 后，有限注入
     * 流耗尽立即返回 EOF。关闭或半关闭始终返回 EOF。
     * 读取/写入错误可指定在第 N 次调用
     * 触发（ReadFailAt / WriteFailAt，1 起）或单次触发
     * （FailNextRead / FailNextWrite）；MaxWrite 限制单次
     * 写入返回字节数以模拟半包写。Close() 后读返回 EOF、写失败。
     */
    class PreviewMockTransport final : public Transmission
    {
    public:
        /**
         * @brief 构造桩
         * @param ex 执行器（通常来自 io_context）
         */
        explicit PreviewMockTransport(net::any_io_executor ex)
            : Ex_(std::move(ex)), Events_(Ex_, 1)
        {
        }

        /** @brief 获取执行器 */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return Ex_;
        }

        /** @brief 检查桩是否仍可读写 */
        [[nodiscard]] auto IsOpen() const noexcept -> bool override
        {
            return !Closed_;
        }

        /**
         * @brief 获取桩配置的传输类型
         * @return 当前传输类型（默认 Tcp）
         * @details Dgram 错误矩阵可将桩标记为 Udp，从而覆盖真实
         *          数据报路径；默认值保持流式测试语义不变。
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return TransportKind;
        }

        /**
         * @brief 读取：注入队列顺序消费，空队列事件驱动等待
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            ++ReadsDone;
            for (;;)
            {
                if (FailNextRead || ReadsDone == ReadFailAt)
                {
                    FailNextRead = false;
                    ec = make_error_code(Error::IoError);
                    co_return 0;
                }
                if (Closed_)
                {
                    co_return 0;
                }
                if (Cancelled_)
                {
                    Cancelled_ = false;
                    ec = make_error_code(Error::Canceled);
                    co_return 0;
                }
                if (ReadError_.has_value())
                {
                    ec = ReadError_.value();
                    ReadError_.reset();
                    co_return 0;
                }
                if (Shutdown_)
                {
                    co_return 0;
                }
                if (ReadPos_ < ToRead.size())
                {
                    const auto N = std::min(Buffer.size(), ToRead.size() - ReadPos_);
                    std::memcpy(Buffer.data(), ToRead.data() + ReadPos_, N);
                    ReadPos_ += N;
                    co_return N;
                }

                if (EofOnDrain)
                {
                    co_return 0;
                }

                // 空读在事件通道上挂起，InjectRead/Close/Cancel/Shutdown 会唤醒它。
                co_await Events_.async_receive(net::use_awaitable);
            }
        }

        /**
         * @brief 写入：捕获数据，可注入错误与半包写
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入字节数（MaxWrite 限制时为半包）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            ++WritesDone;
            if (FailNextWrite || WritesDone == WriteFailAt || Closed_)
            {
                FailNextWrite = false;
                ec = make_error_code(Error::IoError);
                co_return 0;
            }
            if (OverreportWrite)
            {
                co_return Buffer.size() + 1;
            }
            if (ZeroWrite)
            {
                co_return 0;
            }
            std::size_t Limit = MaxWrite;
            if (!WriteLimitSequence.empty())
            {
                Limit = WriteLimitSequence[(WritesDone - 1) % WriteLimitSequence.size()];
            }
            std::size_t Cap;
            if (Limit == 0)
            {
                Cap = Buffer.size();
            }
            else
            {
                Cap = std::min(Buffer.size(), Limit);
            }
            const auto *src = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            Written.insert(Written.end(), src, src + Cap);
            co_return Cap;
        }

        /** @brief 关闭桩并唤醒挂起操作 */
        void Close() override
        {
            Closed_ = true;
            Notify();
        }

        /** @brief 取消下一次挂起读并唤醒它 */
        void Cancel() override
        {
            Cancelled_ = true;
            Notify();
        }

        /** @brief 半关闭读方向，保留写能力 */
        void Shutdown() override
        {
            Shutdown_ = true;
            Notify();
        }

        /**
         * @brief 注入一段可读取数据
         * @param Data 待追加的字节
         * @note 调用方应在构造时绑定的执行器上操作桩状态。
         */
        void InjectRead(std::vector<std::uint8_t> Data)
        {
            ToRead.insert(ToRead.end(), Data.begin(), Data.end());
            Notify();
        }

        /**
         * @brief 注入下一次读取错误并唤醒挂起读
         * @param Error 读取错误码
         */
        void SetReadError(std::error_code Error)
        {
            ReadError_ = Error;
            Notify();
        }

        /// 读取字节流（由测试初始化；耗尽后等待事件）
        std::vector<std::uint8_t> ToRead;
        /// 捕获的全部写入数据
        std::vector<std::uint8_t> Written;
        /// 单次读取后自动复位（注入单点读取错误）
        bool FailNextRead{false};
        /// 单次写入后自动复位（注入单点写入错误）
        bool FailNextWrite{false};
        /// 第 N 次读取返回 io_error（1 起；SIZE_MAX = 禁用）
        std::size_t ReadFailAt{std::numeric_limits<std::size_t>::max()};
        /// 第 N 次写入返回 io_error（1 起；SIZE_MAX = 禁用）
        std::size_t WriteFailAt{std::numeric_limits<std::size_t>::max()};
        /// 单次写入返回字节数上限（0 = 不限制；>0 模拟半包写）
        std::size_t MaxWrite{0};
        /// 按调用次序变化的写入上限（非空时覆盖 MaxWrite，0 = 不限制）
        std::vector<std::size_t> WriteLimitSequence;
        /// 写入返回 0 且不设置错误（用于验证完整写入层的 zero-progress 处理）
        bool ZeroWrite{false};
        /// 写入返回超过请求长度（用于验证完整写入层的防御性检查）
        bool OverreportWrite{false};
        /// 底层传输类型（Dgram 测试设为 Udp，默认 Tcp）
        Type TransportKind{Type::Tcp};
        /// 有限注入流耗尽后返回 EOF；false 时空读事件驱动等待
        bool EofOnDrain{false};
        /// 已执行读取次数
        std::size_t ReadsDone{0};
        /// 已执行写入次数
        std::size_t WritesDone{0};

        /** @brief 检查是否已关闭 */
        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return Closed_;
        }

        /** @brief 检查是否已半关闭读方向 */
        [[nodiscard]] auto IsShutdown() const noexcept -> bool
        {
            return Shutdown_;
        }

        /** @brief 检查是否存在待消费的取消请求 */
        [[nodiscard]] auto IsCancelled() const noexcept -> bool
        {
            return Cancelled_;
        }

    private:
        /** @brief 发送合并唤醒事件 */
        void Notify()
        {
            (void)Events_.try_send(boost::system::error_code{});
        }

        net::any_io_executor Ex_;
        net::experimental::channel<void(boost::system::error_code)> Events_;
        std::size_t ReadPos_{0};
        bool Closed_{false};
        bool Shutdown_{false};
        bool Cancelled_{false};
        std::optional<std::error_code> ReadError_;
    };

} // namespace Preview
