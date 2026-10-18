/** @file PadPolicy.hpp @brief 填充范围在冷配置一次编译，热写路径只消费数值。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <charconv>
#include <cstdint>
#include <expected>
#include <string_view>
#include <vector>
namespace Prism::Transport
{
    /**
     * @brief 单个填充目标区间的纯值范围，冷配置一次编译。
     * @details 输入所有权：纯值，不拥有任何运行时资源，复制即独立；由 PadConfig::Targets 按序持有。
     *          输出与错误：MinVal>MaxVal 的倒置区间在 ParsePadTargets 解析期被拒（InvalidArgument），
     *          PadDriver 构造再做一次同项校验并记入 Failure_，热写路径不再判定。
     *          取消、半关闭、最终关闭者、executor：本类型不参与 I/O 与异步生命周期，这四类语义不适用；
     *          实际的取消、写半关闭与最终关闭归属全部由 PadTransport 及其 Writer 承担。
     */
    struct PadTarget final { std::uint16_t MinVal{0}, MaxVal{0}; };
    /**
     * @brief 编译后的填充策略集合，以不可变共享 owner 冻结，热写路径只消费数值。
     * @details 输入所有权：整份策略由 PadOptions 以 shared_ptr<const PadConfig> 冻结共享，运行期不复制
     *          Targets、不重新解析字符串；Targets 本身拥有各区间值。Enabled() 为假（Targets 为空）时
     *          driver 原样透传输入不加填充。
     *          输出与错误：本类型不返回结果；Targets 超过 64 项、倒置区间等非法形状由 PadDriver 构造
     *          校验为 InvalidArgument，字符串形状与条数上限由 ParsePadTargets 以 OversizedMsg/InvalidArgument
     *          拒绝，取消、EOF、容量拒绝与底层错误四类不受本类型影响。
     *          取消与半关闭：StopAfter 与 MaxPadBytes 只约束填充长度与停止时机，不改变写半关闭语义，
     *          也不会因取消回滚已写入记录。
     *          最终关闭者与 executor：纯值配置，不拥有描述符、不绑定执行域；实际关闭者与执行域归 PadTransport。
     * @note 未定义：MaxPadBytes 只限制单次随机附加长度，不约束整条记录的上界；记录形状超限的处置
     *       由 PadDriver 的透传分支决定，留待 M13 与协议侧一并收口。
     */
    struct PadConfig final
    {
        std::vector<PadTarget> Targets{{17,17}, {30,50}, {30,50}, {80,150}};
        std::uint8_t StopAfter{12};
        std::uint16_t MaxPadBytes{256};
        [[nodiscard]] auto Enabled() const noexcept -> bool { return !Targets.empty(); }
    };
    /** @brief 借用冷文本至返回，空文本表示禁用；拒绝非法、倒置、溢出及超过64条范围。 */
    [[nodiscard]] inline auto ParsePadTargets(std::string_view Text) -> std::expected<std::vector<PadTarget>, Fault::Failure>
    {
        std::vector<PadTarget> Result;
        if (Text.empty()) return Result;
        while (!Text.empty())
        {
            if (Result.size() == 64) return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg});
            const auto Comma = Text.find(',');
            const auto Item = Text.substr(0, Comma);
            const auto Dash = Item.find('-');
            const auto Minimum = Item.substr(0, Dash);
            auto Maximum = Minimum;
            if (Dash != std::string_view::npos) Maximum = Item.substr(Dash + 1);
            PadTarget Range;
            if (Minimum.empty() || Maximum.empty()) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            const auto Low = std::from_chars(Minimum.data(), Minimum.data() + Minimum.size(), Range.MinVal);
            const auto High = std::from_chars(Maximum.data(), Maximum.data() + Maximum.size(), Range.MaxVal);
            if (Low.ec != std::errc{} || High.ec != std::errc{} || Low.ptr != Minimum.data() + Minimum.size() ||
                High.ptr != Maximum.data() + Maximum.size() || Range.MinVal > Range.MaxVal)
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            Result.push_back(Range);
            if (Comma == std::string_view::npos) break;
            Text.remove_prefix(Comma + 1);
            if (Text.empty()) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        }
        return Result;
    }
}
