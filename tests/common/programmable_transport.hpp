/**
 * @file programmable_transport.hpp
 * @brief 可编程传输桩（preview 共享测试设施）
 * @details 供各协议 dgram / conn 错误路径测试复用，可编程行为：
 * - 注入读取字节流（to_read，按需消费；耗尽后返回 0 = EOF）
 * - 按调用次数注入读取错误（fail_next_read / read_fail_at）
 * - 按调用次数注入写入错误（fail_next_write / write_fail_at）
 * - 限制单次写入返回长度（max_write，模拟半包写）
 * - 捕获全部写入数据（written）
 * - close() 后：读返回 0，写返回 io_error
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

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>

namespace preview
{

    namespace net = boost::asio;

    /**
     * @class programmable_transport
     * @brief 可编程传输桩（transmission 接口）
     * @details 行为完全由测试方编排：读取从注入队列顺序消费，
     * 队列耗尽返回 0（EOF）；读取/写入错误可指定在第 N 次调用
     * 触发（read_fail_at / write_fail_at，1 起）或单次触发
     * （fail_next_read / fail_next_write）；max_write 限制单次
     * 写入返回字节数以模拟半包写。close() 后读返回 EOF、写失败。
     */
    class programmable_transport final : public transmission
    {
    public:
        /**
         * @brief 构造桩
         * @param ex 执行器（通常来自 io_context）
         */
        explicit programmable_transport(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        /** @brief 获取执行器 */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 读取：注入队列顺序消费，耗尽返回 0（EOF）
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ++reads_done;
            if (fail_next_read || reads_done == read_fail_at)
            {
                fail_next_read = false;
                ec = make_error_code(error::io_error);
                co_return 0;
            }
            if (closed || read_pos_ >= to_read.size())
            {
                co_return 0;
            }
            const auto n = std::min(buffer.size(), to_read.size() - read_pos_);
            std::memcpy(buffer.data(), to_read.data() + read_pos_, n);
            read_pos_ += n;
            co_return n;
        }

        /**
         * @brief 写入：捕获数据，可注入错误与半包写
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入字节数（max_write 限制时为半包）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ++writes_done;
            if (fail_next_write || writes_done == write_fail_at || closed)
            {
                fail_next_write = false;
                ec = make_error_code(error::io_error);
                co_return 0;
            }
            std::size_t cap;
            if (max_write == 0)
            {
                cap = buffer.size();
            }
            else
            {
                cap = std::min(buffer.size(), max_write);
            }
            const auto *src = reinterpret_cast<const std::uint8_t *>(buffer.data());
            written.insert(written.end(), src, src + cap);
            co_return cap;
        }

        /** @brief 关闭桩（后续读返回 EOF，写返回 io_error） */
        void close() override
        {
            closed = true;
        }

        /** @brief 取消挂起操作 */
        void cancel() override
        {
        }

        /// 注入读取字节流（耗尽后 EOF）
        std::vector<std::uint8_t> to_read;
        /// 捕获的全部写入数据
        std::vector<std::uint8_t> written;
        /// 单次读取后自动复位（注入单点读取错误）
        bool fail_next_read{false};
        /// 单次写入后自动复位（注入单点写入错误）
        bool fail_next_write{false};
        /// 第 N 次读取返回 io_error（1 起；SIZE_MAX = 禁用）
        std::size_t read_fail_at{std::numeric_limits<std::size_t>::max()};
        /// 第 N 次写入返回 io_error（1 起；SIZE_MAX = 禁用）
        std::size_t write_fail_at{std::numeric_limits<std::size_t>::max()};
        /// 单次写入返回字节数上限（0 = 不限制；>0 模拟半包写）
        std::size_t max_write{0};
        /// 已执行读取次数
        std::size_t reads_done{0};
        /// 已执行写入次数
        std::size_t writes_done{0};

    private:
        net::any_io_executor ex_;
        std::size_t read_pos_{0};
        bool closed{false};
    };

} // namespace preview
