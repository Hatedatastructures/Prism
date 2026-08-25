/**
 * @file Parser.hpp
 * @brief 跨协议增量解析器基类（借鉴 Boost.Beast http::Parser 精髓）
 * @details 解析器设计为类封装 + 模板配置：
 *          - 模板参数 Config 描述帧结构（头长 / 载荷长 / 解析函数）
 *          - 状态机：idle → Header → payload → Done
 *          - 增量喂数据：Want() 查询缺口，Put() 喂入，Done() 取结果
 *          - 配合 FlatBuffer 使用，热路径零堆分配
 *
 *          Config 要求（concept 约束）：
 *          @Code
 *          struct FrameConfig {
 *              using FrameType = my_frame;                 // 帧类型
 *              static constexpr size_t HeaderLen = 8;      // 固定头长
 *              // 解析头部（可返回 need_more 变长头场景）
 *              static auto ParseHeader(span, FrameType&) -> Error;
 *              // 由头部计算载荷长度
 *              static auto PayloadLen(const FrameType&) -> size_t;
 *              // 解析载荷（可选，默认不校验）
 *              static auto ParsePayload(FrameType&, span) -> Error;
 *          };
 *          @endcode
 * @note 纯逻辑零 I/O；I/O 由上层 Session 驱动。
 */

#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

#include <common/Core/Error.hpp>
#include <common/Core/FlatBuffer.hpp>

namespace Preview
{

    namespace detail
    {

        /// 帧配置 concept：描述帧结构
        /// @tparam C 配置类型
        template <typename C>
        concept FrameConfig = requires(C &c) {
            typename C::FrameType;
            { C::HeaderLen } -> std::convertible_to<const std::size_t>;
            { C::ParseHeader(std::span<const std::uint8_t>{}, c.frame_) } -> std::same_as<Error>;
            { C::PayloadLen(c.frame_) } -> std::convertible_to<std::size_t>;
            { C::ParsePayload(c.frame_, std::span<const std::uint8_t>{}) } -> std::same_as<Error>;
        };

    } // namespace detail

    /// 增量解析器状态
    enum class ParseState
    {
        /// 等待头部
        Header,
        /// 等待载荷
        payload,
        /// 解析完成
        Done,
        /// 解析失败（不可恢复）
        Failed,
    };

    /// @brief 跨协议增量帧解析器
    /// @tparam Config 帧配置（见 file 文档）
    template <typename Config>
    class Parser
    {
    public:
        /// 帧类型
        using FrameType = typename Config::FrameType;

        /**
         * @brief 构造
         * @param Capacity 内部缓冲初始容量
         */
        explicit Parser(std::size_t Capacity = 256) : buf_(Capacity)
        {
        }

        /**
         * @brief 不可拷贝
         */
        Parser(const Parser &) = delete;
        auto operator=(const Parser &) -> Parser & = delete;

        /**
         * @brief 移动构造
         */
        Parser(Parser &&) noexcept = default;

        /**
         * @brief 移动赋值
         */
        auto operator=(Parser &&) noexcept -> Parser & = default;

        /**
         * @brief 当前状态
         * @return 当前解析状态
         */
        [[nodiscard]] auto State() const noexcept -> ParseState
        {
            return state_;
        }

        /**
         * @brief 是否解析完成
         * @return 解析完成返回 true
         */
        [[nodiscard]] auto Done() const noexcept -> bool
        {
            return state_ == ParseState::Done;
        }

        /**
         * @brief 是否失败
         * @return 解析失败返回 true
         */
        [[nodiscard]] auto Failed() const noexcept -> bool
        {
            return state_ == ParseState::Failed;
        }

        /**
         * @brief 还需多少字节才能完成（0 = Done/Failed）
         * @return 尚需字节数
         */
        [[nodiscard]] auto Want() const noexcept -> std::size_t
        {
            if (state_ == ParseState::Done || state_ == ParseState::Failed)
            {
                return 0;
            }
            if (state_ == ParseState::Header)
            {
                if (Config::HeaderLen > buf_.Size())
                {
                    return Config::HeaderLen - buf_.Size();
                }
                return 0;
            }
            const auto Total = Config::HeaderLen + Config::PayloadLen(frame_);
            if (Total > buf_.Size())
            {
                return Total - buf_.Size();
            }
            return 0;
        }

        /**
         * @brief 喂入数据（增量解析）
         * @param Data 输入数据
         * @return 错误码；need_more = 数据不足（继续喂）
         * @note 内部缓冲未消费的数据（跨包残留）保留待下次喂入
         */
        auto Put(std::span<const std::uint8_t> Data) -> Error
        {
            if (state_ == ParseState::Failed)
            {
                return Error::protocol_error;
            }
            if (state_ == ParseState::Done)
            {
                return Error::none;
            }

            // 追加到内部缓冲
            if (buf_.Append(Data) < Data.size())
            {
                return Error::need_more; // 缓冲增长失败（OOM 防御）
            }

            // 状态机推进
            while (true)
            {
                if (state_ == ParseState::Header)
                {
                    if (buf_.Size() < Config::HeaderLen)
                    {
                        return Error::need_more;
                    }
                    const auto ec = Config::ParseHeader(buf_.Data().first(Config::HeaderLen), frame_);
                    if (ec == Error::need_more)
                    {
                        return Error::need_more; // 变长头继续等
                    }
                    if (ec != Error::none)
                    {
                        state_ = ParseState::Failed;
                        return ec;
                    }
                    buf_.Consume(Config::HeaderLen);
                    state_ = ParseState::payload;
                }
                else if (state_ == ParseState::payload)
                {
                    const auto need = Config::PayloadLen(frame_);
                    if (buf_.Size() < need)
                    {
                        return Error::need_more;
                    }
                    const auto ec = Config::ParsePayload(frame_, buf_.Data().first(need));
                    if (ec != Error::none)
                    {
                        state_ = ParseState::Failed;
                        return ec;
                    }
                    buf_.Consume(need);
                    state_ = ParseState::Done;
                    return Error::none;
                }
                else
                {
                    return Error::none;
                }
            }
        }

        /**
         * @brief 解析结果（Done 后有效）
         * @return 解析出的帧（只读引用）
         */
        [[nodiscard]] auto Frame() const noexcept -> const FrameType &
        {
            return frame_;
        }

        /**
         * @brief 可写访问解析结果
         * @return 帧的可写引用
         */
        [[nodiscard]] auto Frame() noexcept -> FrameType &
        {
            return frame_;
        }

        /**
         * @brief 重置解析器（复用对象）
         */
        auto Reset() noexcept -> void
        {
            buf_.Clear();
            frame_ = FrameType{};
            state_ = ParseState::Header;
        }

        /**
         * @brief 内部缓冲剩余数据（跨帧残留，二次解析时使用）
         * @return 剩余数据只读视图
         */
        [[nodiscard]] auto Residual() const noexcept -> std::span<const std::uint8_t>
        {
            return buf_.Data();
        }

    private:
        FlatBuffer buf_;
        FrameType frame_{};
        ParseState state_{ParseState::Header};
    };

} // namespace Preview
