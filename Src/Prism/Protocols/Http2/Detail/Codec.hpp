/**
 * @file Codec.hpp
 * @brief HPACK 头压缩编解码（自包含，RFC 7541）
 * @details 实现 HPACK 核心：
 *          - 整数编码（Prefix N 位）
 *          - 字符串编码（Huffman 标记 + 长度前缀）
 *          - 静态表（61 项，RFC 7541 Appendix A）
 *          - 动态表（基本实现：插入/索引）
 *          - 索引头字段 / 字面量头字段（增量索引/无索引/永不索引）
 * @note Huffman 字符串复用独立 HTTP 压缩模块中的 RFC 7541 编解码实现。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http2/Types.hpp>

namespace Prism::Http2::Detail
{

    /** @brief HPACK 整数的 wire prefix/value 边界。 */
    struct HpackInteger final
    {
        std::uint64_t Value{0};
        std::uint8_t PrefixBits{0};
        std::uint8_t FirstByte{0};
    };

    /**
     * @brief 按 RFC 7541 Prefix N 位编码整数。
     * @param Input 值、前缀位宽和首字节 wire 标记
     * @param Output 输出缓冲区
     */
    auto EncodeInt(const HpackInteger &Input, std::vector<std::byte> &Output) -> void;

    /**
     * @brief 解码整数（Prefix N 位）
     * @param Data 输入缓冲区
     * @param PrefixBits 前缀位数
     * @param Offset 解析偏移（输入输出）
     * @return 整数值
     */
    [[nodiscard]] auto DecodeInt(
        std::span<const std::byte> Data,
        std::uint8_t PrefixBits,
        std::size_t &Offset) -> std::optional<std::uint64_t>;

    /**
     * @brief 编码字符串（plain，Huffman 标记位 = 0）
     * @param Text 字符串
     * @param Output 输出缓冲区
     */
    auto EncodeString(
        std::string_view Text,
        std::vector<std::byte> &Output) -> void;

    /**
     * @brief 解码字符串
     * @param Data 输入缓冲区
     * @param Offset 解析偏移（输入输出）
     * @return 解码字符串；失败返回 std::nullopt
     */
    [[nodiscard]] auto DecodeString(
        std::span<const std::byte> Data,
        std::size_t &Offset)
        -> std::optional<std::string>;

    /**
     * @brief HPACK 编码器（静态表 + 增量索引）
     * @details 维护发送侧动态表（简化为静态表 + 索引头字段；
     *          字面量增量索引头字段实现动态表更新）。
     */
    class HpackEncoder
    {
    public:
        /**
         * @brief 编码头列表为 HPACK 块
         * @param Headers 头列表
         * @return HPACK 编码字节
         */
        [[nodiscard]] auto Encode(const HeaderList &Headers) -> std::vector<std::byte>;

    private:
        /// 增量索引字面量头字段（RFC 7541 §6.2.1）
        auto EncodeHeader(
            std::string_view Name,
            std::string_view Value,
            std::vector<std::byte> &Output) -> void;
    };

    /**
     * @brief HPACK 解码器（静态表 + 动态表）
     */
    class HpackDecoder
    {
    public:
        /**
         * @brief 解码 HPACK 块
         * @param Data HPACK 字节
         * @return 头列表；解析失败返回 std::nullopt
         */
        [[nodiscard]] auto Decode(std::span<const std::byte> Data)
            -> std::optional<HeaderList>;

    private:
        /// 动态表容量上限（RFC 7541 §4.2 默认 4096 字节）
        static constexpr std::size_t DynCapacity = 4096;
        /// HPACK 条目开销（RFC 7541 §4.1：Name + Value + 32）
        static constexpr std::size_t EntryOverhead = 32;

        /**
         * @brief 解析索引头字段（RFC 7541 §6.1）。
         * @param Data 当前 HPACK 块
         * @param Offset 当前读取位置，由整数解析推进
         * @return 静态表或动态表中的头字段；索引无效时返回空值
         */
        [[nodiscard]] auto DecodeIndexed(
            std::span<const std::byte> Data,
            std::size_t &Offset) -> std::optional<Header>;

        /**
         * @brief 解码并应用动态表大小更新（RFC 7541 §6.3）。
         * @param Data 当前 HPACK 块
         * @param Offset 当前读取位置
         * @return 成功消费更新指令并完成驱逐时为 true
         */
        [[nodiscard]] auto ApplyTableSizeUpdate(
            std::span<const std::byte> Data,
            std::size_t &Offset) -> bool;

        /**
         * @brief 解析三种字面量头字段的共同 name/value 阶段。
         * @param Data 当前 HPACK 块
         * @param Offset 当前读取位置
         * @param PrefixBits name 索引前缀位数（增量索引为 6，其余为 4）
         * @return 解析后的头字段；索引或字符串不完整时返回空值
         */
        [[nodiscard]] auto DecodeLiteral(
            std::span<const std::byte> Data,
            std::size_t &Offset,
            std::uint8_t PrefixBits) -> std::optional<Header>;

        /// 动态表（Dynamic_[0] = 最新条目 = 索引 62，尾部为最旧）
        std::vector<Header> Dynamic_;
        /// 动态表当前字节数（含每条目 32 开销）
        std::size_t DynUsed_{0};
        /// 当前 header block 宣布的动态表容量；DynCapacity 是固定最大值。
        std::size_t DynamicCapacity_{DynCapacity};

        /// 计算一个头的动态表占用
        [[nodiscard]] static auto EntrySizeOf(const Header &Field) -> std::size_t
        {
            return Field.Name.size() + Field.Value.size() + EntryOverhead;
        }

        /**
         * @brief 插入动态表（§6.2.1 增量索引）：最新条目置于头部，
         *        插入前从尾部（最旧）驱逐直至不超容量；单条超容量则清空
         */
        auto InsertDynamic(const Header &Field) -> void;

        /**
         * @brief 按新容量上限驱逐最旧条目（§6.3 大小更新指令）
         */
        auto EvictDynamic(std::size_t NewCapacity) -> void;

        /**
         * @brief 按索引查表（静态 1-61 + 动态 62+）
         * @param Index 索引
         * @return 头；越界返回 std::nullopt
         */
        [[nodiscard]] auto LookupIndex(std::size_t Index) -> std::optional<Header>;
    };

} // namespace Prism::Http2::Detail
