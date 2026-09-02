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

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/FlatBuffer.hpp>

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
            { C::ParseHeader(std::span<const std::uint8_t>{}, c.Frame_) } -> std::same_as<Error>;
            { C::PayloadLen(c.Frame_) } -> std::convertible_to<std::size_t>;
            { C::ParsePayload(c.Frame_, std::span<const std::uint8_t>{}) } -> std::same_as<Error>;
        };

    } // namespace detail

    /// 增量解析器状态
    enum class ParseState
    {
        /// 等待头部
        Header,
        /// 等待载荷
        Payload,
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
        explicit Parser(std::size_t Capacity = 256) : Buf_(Capacity)
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
            return State_;
        }

        /**
         * @brief 是否解析完成
         * @return 解析完成返回 true
         */
        [[nodiscard]] auto Done() const noexcept -> bool
        {
            return State_ == ParseState::Done;
        }

        /**
         * @brief 是否失败
         * @return 解析失败返回 true
         */
        [[nodiscard]] auto Failed() const noexcept -> bool
        {
            return State_ == ParseState::Failed;
        }

        /**
         * @brief 还需多少字节才能完成（0 = Done/Failed）
         * @return 尚需字节数
         */
        [[nodiscard]] auto Want() const noexcept -> std::size_t
        {
            if (State_ == ParseState::Done || State_ == ParseState::Failed)
            {
                return 0;
            }
            if (State_ == ParseState::Header)
            {
                if (Config::HeaderLen > Buf_.Size())
                {
                    return Config::HeaderLen - Buf_.Size();
                }
                return 0;
            }
            const auto Total = Config::HeaderLen + Config::PayloadLen(Frame_);
            if (Total > Buf_.Size())
            {
                return Total - Buf_.Size();
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
            if (State_ == ParseState::Failed)
            {
                return Error::ProtocolError;
            }
            if (State_ == ParseState::Done)
            {
                return Error::None;
            }

            // 追加到内部缓冲
            if (Buf_.Append(Data) < Data.size())
            {
                return Error::NeedMore; // 缓冲增长失败（OOM 防御）
            }

            // 状态机推进
            while (true)
            {
                if (State_ == ParseState::Header)
                {
                    if (Buf_.Size() < Config::HeaderLen)
                    {
                        return Error::NeedMore;
                    }
                    const auto Ec = Config::ParseHeader(Buf_.Data().first(Config::HeaderLen), Frame_);
                    if (Ec == Error::NeedMore)
                    {
                        return Error::NeedMore; // 变长头继续等
                    }
                    if (Ec != Error::None)
                    {
                        State_ = ParseState::Failed;
                        return Ec;
                    }
                    Buf_.Consume(Config::HeaderLen);
                    State_ = ParseState::Payload;
                }
                else if (State_ == ParseState::Payload)
                {
                    const auto Need = Config::PayloadLen(Frame_);
                    if (Buf_.Size() < Need)
                    {
                        return Error::NeedMore;
                    }
                    const auto Ec = Config::ParsePayload(Frame_, Buf_.Data().first(Need));
                    if (Ec != Error::None)
                    {
                        State_ = ParseState::Failed;
                        return Ec;
                    }
                    Buf_.Consume(Need);
                    State_ = ParseState::Done;
                    return Error::None;
                }
                else
                {
                    return Error::None;
                }
            }
        }

        /**
         * @brief 解析结果（Done 后有效）
         * @return 解析出的帧（只读引用）
         */
        [[nodiscard]] auto Frame() const noexcept -> const FrameType &
        {
            return Frame_;
        }

        /**
         * @brief 可写访问解析结果
         * @return 帧的可写引用
         */
        [[nodiscard]] auto Frame() noexcept -> FrameType &
        {
            return Frame_;
        }

        /**
         * @brief 重置解析器（复用对象）
         */
        auto Reset() noexcept -> void
        {
            Buf_.Clear();
            Frame_ = FrameType{};
            State_ = ParseState::Header;
        }

        /**
         * @brief 内部缓冲剩余数据（跨帧残留，二次解析时使用）
         * @return 剩余数据只读视图
         */
        [[nodiscard]] auto Residual() const noexcept -> std::span<const std::uint8_t>
        {
            return Buf_.Data();
        }

    private:
        FlatBuffer Buf_;
        FrameType Frame_{};
        ParseState State_{ParseState::Header};
    };

} // namespace Preview
