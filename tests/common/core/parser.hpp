/**
 * @file parser.hpp
 * @brief 跨协议增量解析器基类（借鉴 Boost.Beast http::parser 精髓）
 * @details 解析器设计为类封装 + 模板配置：
 *          - 模板参数 Config 描述帧结构（头长 / 载荷长 / 解析函数）
 *          - 状态机：idle → header → payload → done
 *          - 增量喂数据：want() 查询缺口，put() 喂入，done() 取结果
 *          - 配合 flat_buffer 使用，热路径零堆分配
 *
 *          Config 要求（concept 约束）：
 *          @code
 *          struct frame_config {
 *              using frame_type = my_frame;                 // 帧类型
 *              static constexpr size_t header_len = 8;      // 固定头长
 *              // 解析头部（可返回 need_more 变长头场景）
 *              static auto parse_header(span, frame_type&) -> error;
 *              // 由头部计算载荷长度
 *              static auto payload_len(const frame_type&) -> size_t;
 *              // 解析载荷（可选，默认不校验）
 *              static auto parse_payload(frame_type&, span) -> error;
 *          };
 *          @endcode
 * @note 纯逻辑零 I/O；I/O 由上层 session 驱动。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/flat_buffer.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psmtest
{

    namespace detail
    {

        /// 帧配置 concept：描述帧结构
        /// @tparam C 配置类型
        template <typename C>
        concept frame_config = requires(C &c)
        {
            typename C::frame_type;
            { C::header_len } -> std::convertible_to<const std::size_t>;
            { C::parse_header(std::span<const std::uint8_t>{}, c.frame_) }
                -> std::same_as<error>;
            { C::payload_len(c.frame_) } -> std::convertible_to<std::size_t>;
            { C::parse_payload(c.frame_, std::span<const std::uint8_t>{}) }
                -> std::same_as<error>;
        };

    } // namespace detail

    /// 增量解析器状态
    enum class parse_state
    {
        /// 等待头部
        header,
        /// 等待载荷
        payload,
        /// 解析完成
        done,
        /// 解析失败（不可恢复）
        failed,
    };

    /// @brief 跨协议增量帧解析器
    /// @tparam Config 帧配置（见 file 文档）
    template <typename Config>
    class parser
    {
    public:
        /// 帧类型
        using frame_type = typename Config::frame_type;

        /// @brief 构造
        /// @param capacity 内部缓冲初始容量
        explicit parser(std::size_t capacity = 256)
            : buf_(capacity)
        {
        }

        /// 不可拷贝
        parser(const parser &) = delete;
        auto operator=(const parser &) -> parser & = delete;

        /// 移动构造
        parser(parser &&) noexcept = default;

        /// 移动赋值
        auto operator=(parser &&) noexcept -> parser & = default;

        /// 当前状态
        [[nodiscard]] auto state() const noexcept -> parse_state
        {
            return state_;
        }

        /// 是否解析完成
        [[nodiscard]] auto done() const noexcept -> bool
        {
            return state_ == parse_state::done;
        }

        /// 是否失败
        [[nodiscard]] auto failed() const noexcept -> bool
        {
            return state_ == parse_state::failed;
        }

        /// @brief 还需多少字节才能完成（0 = done/failed）
        [[nodiscard]] auto want() const noexcept -> std::size_t
        {
            if (state_ == parse_state::done || state_ == parse_state::failed)
                return 0;
            if (state_ == parse_state::header)
            {
                return Config::header_len > buf_.size()
                           ? Config::header_len - buf_.size()
                           : 0;
            }
            const auto total = Config::header_len + Config::payload_len(frame_);
            return total > buf_.size() ? total - buf_.size() : 0;
        }

        /// @brief 喂入数据（增量解析）
        /// @param data 输入数据
        /// @return 错误码；need_more = 数据不足（继续喂）
        /// @note 内部缓冲未消费的数据（跨包残留）保留待下次喂入
        auto put(std::span<const std::uint8_t> data) -> error
        {
            if (state_ == parse_state::failed)
                return error::protocol_error;
            if (state_ == parse_state::done)
                return error::none;

            // 追加到内部缓冲
            if (buf_.append(data) < data.size())
                return error::need_more; // 缓冲增长失败（OOM 防御）

            // 状态机推进
            while (true)
            {
                if (state_ == parse_state::header)
                {
                    if (buf_.size() < Config::header_len)
                        return error::need_more;
                    const auto ec = Config::parse_header(buf_.data().first(Config::header_len), frame_);
                    if (ec == error::need_more)
                        return error::need_more; // 变长头继续等
                    if (ec != error::none)
                    {
                        state_ = parse_state::failed;
                        return ec;
                    }
                    buf_.consume(Config::header_len);
                    state_ = parse_state::payload;
                }
                else if (state_ == parse_state::payload)
                {
                    const auto need = Config::payload_len(frame_);
                    if (buf_.size() < need)
                        return error::need_more;
                    const auto ec = Config::parse_payload(frame_, buf_.data().first(need));
                    if (ec != error::none)
                    {
                        state_ = parse_state::failed;
                        return ec;
                    }
                    buf_.consume(need);
                    state_ = parse_state::done;
                    return error::none;
                }
                else
                {
                    return error::none;
                }
            }
        }

        /// @brief 解析结果（done 后有效）
        [[nodiscard]] auto frame() const noexcept -> const frame_type &
        {
            return frame_;
        }

        /// 可写访问解析结果
        [[nodiscard]] auto frame() noexcept -> frame_type &
        {
            return frame_;
        }

        /// @brief 重置解析器（复用对象）
        auto reset() noexcept -> void
        {
            buf_.clear();
            frame_ = frame_type{};
            state_ = parse_state::header;
        }

        /// 内部缓冲剩余数据（跨帧残留，二次解析时使用）
        [[nodiscard]] auto residual() const noexcept -> std::span<const std::uint8_t>
        {
            return buf_.data();
        }

    private:
        flat_buffer buf_;
        frame_type frame_{};
        parse_state state_{parse_state::header};
    };

} // namespace psmtest
