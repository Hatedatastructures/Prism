/**
 * @file ProgrammableTransport.hpp
 * @brief 可编程传输桩（Preview 共享测试设施）
 * @details 供各协议 Dgram / Conn 错误路径测试复用，可编程行为：
 * - 注入读取字节流（ToRead，按需消费；耗尽后返回 0 = EOF）
 * - 按调用次数注入读取错误（FailNextRead / ReadFailAt）
 * - 按调用次数注入写入错误（FailNextWrite / WriteFailAt）
 * - 限制单次写入返回长度（MaxWrite，模拟半包写）
 * - 捕获全部写入数据（written）
 * - Close() 后：读返回 0，写返回 io_error
 * @note 仅测试代码使用，禁止被生产代码引用。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview
{

    namespace net = boost::asio;

    /**
     * @class ProgrammableTransport
     * @brief 可编程传输桩（Transmission 接口）
     * @details 行为完全由测试方编排：读取从注入队列顺序消费，
     * 队列耗尽返回 0（EOF）；读取/写入错误可指定在第 N 次调用
     * 触发（ReadFailAt / WriteFailAt，1 起）或单次触发
     * （FailNextRead / FailNextWrite）；MaxWrite 限制单次
     * 写入返回字节数以模拟半包写。Close() 后读返回 EOF、写失败。
     */
    class ProgrammableTransport final : public Transmission
    {
    public:
        /**
         * @brief 构造桩
         * @param ex 执行器（通常来自 io_context）
         */
        explicit ProgrammableTransport(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        /** @brief 获取执行器 */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 读取：注入队列顺序消费，耗尽返回 0（EOF）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ++ReadsDone;
            if (FailNextRead || ReadsDone == ReadFailAt)
            {
                FailNextRead = false;
                ec = make_error_code(Error::io_error);
                co_return 0;
            }
            if (closed || ReadPos_ >= ToRead.size())
            {
                co_return 0;
            }
            const auto n = std::min(Buffer.size(), ToRead.size() - ReadPos_);
            std::memcpy(Buffer.data(), ToRead.data() + ReadPos_, n);
            ReadPos_ += n;
            co_return n;
        }

        /**
         * @brief 写入：捕获数据，可注入错误与半包写
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入字节数（MaxWrite 限制时为半包）
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ++WritesDone;
            if (FailNextWrite || WritesDone == WriteFailAt || closed)
            {
                FailNextWrite = false;
                ec = make_error_code(Error::io_error);
                co_return 0;
            }
            std::size_t cap;
            if (MaxWrite == 0)
            {
                cap = Buffer.size();
            }
            else
            {
                cap = std::min(Buffer.size(), MaxWrite);
            }
            const auto *src = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            written.insert(written.end(), src, src + cap);
            co_return cap;
        }

        /** @brief 关闭桩（后续读返回 EOF，写返回 io_error） */
        void Close() override
        {
            closed = true;
        }

        /** @brief 取消挂起操作 */
        void Cancel() override
        {
        }

        /// 注入读取字节流（耗尽后 EOF）
        std::vector<std::uint8_t> ToRead;
        /// 捕获的全部写入数据
        std::vector<std::uint8_t> written;
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
        /// 已执行读取次数
        std::size_t ReadsDone{0};
        /// 已执行写入次数
        std::size_t WritesDone{0};

    private:
        net::any_io_executor ex_;
        std::size_t ReadPos_{0};
        bool closed{false};
    };

} // namespace Preview
