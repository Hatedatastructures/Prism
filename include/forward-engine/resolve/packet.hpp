/**
 * @file packet.hpp
 * @brief DNS 报文编解码
 * @details DNS 二进制报文的构造与解析（RFC 1035），完全不依赖系统 resolver。
 * 支持域名压缩指针、多种记录类型（A/AAAA/CNAME/NS/MX/TXT/SOA/PTR/OPT）。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <boost/asio.hpp>

#include <forward-engine/memory/container.hpp>

namespace ngx::resolve
{
    namespace net = boost::asio;

    /**
     * @enum qtype
     * @brief DNS 查询/资源记录类型枚举
     * @details 对应 RFC 1035 定义的 QTYPE / TYPE 字段，
     * 仅列出本项目实际使用到的类型。
     */
    enum class qtype : std::uint16_t
    {
        a = 1,     // IPv4 地址记录
        ns = 2,    // 权威名称服务器
        cname = 5, // 规范名称（别名）
        soa = 6,   // 区域起始授权
        mx = 15,   // 邮件交换
        txt = 16,  // 文本记录
        aaaa = 28, // IPv6 地址记录
        opt = 41,  // EDNS0 选项
    };

    /**
     * @struct question
     * @brief DNS 查询段（Question Section）
     * @details 每个查询段包含一个域名、查询类型和查询类。
     * 域名存储为小写、无末尾点号的 dotted 格式（如 "www.example.com"）。
     */
    struct question
    {
        memory::string name;     // 域名，小写无末尾点号
        qtype qtype{};           // 查询类型
        std::uint16_t qclass{1}; // 查询类，默认 IN（Internet）

        explicit question(memory::resource_pointer mr = memory::current_resource())
            : name(mr)
        {
        }
    };

    /**
     * @struct record
     * @brief DNS 资源记录（Resource Record）
     * @details 每条记录包含拥有者名称、类型、类、TTL 及原始 RDATA。
     * rdata 保存未解码的二进制数据，可通过 extract_ipv4 / extract_ipv6
     * 等工具函数提取具体语义。
     */
    struct record
    {
        memory::string name;                // 拥有者名称，小写无末尾点号
        qtype type{};                       // 记录类型
        std::uint16_t rclass{1};            // 记录类，默认 IN
        std::uint32_t ttl{0};               // 生存时间（秒）
        memory::vector<std::uint8_t> rdata; // 原始 RDATA

        explicit record(memory::resource_pointer mr = memory::current_resource())
            : name(mr), rdata(mr)
        {
        }
    };

    /**
     * @brief 从 A 记录中提取 IPv4 地址
     * @param rec DNS 资源记录
     * @return 若 rdata 恰好 4 字节则返回对应地址，否则返回 std::nullopt
     */
    [[nodiscard]] auto extract_ipv4(const record &rec) -> std::optional<net::ip::address_v4>;

    /**
     * @brief 从 AAAA 记录中提取 IPv6 地址
     * @param rec DNS 资源记录
     * @return 若 rdata 恰好 16 字节则返回对应地址，否则返回 std::nullopt
     */
    [[nodiscard]] auto extract_ipv6(const record &rec) -> std::optional<net::ip::address_v6>;

    /**
     * @class message
     * @brief DNS 报文（RFC 1035）
     * @details 表示一条完整的 DNS 报文，包含 Header、Question、Answer、
     * Authority、Additional 四个段。提供序列化（pack）与反序列化（unpack）
     * 能力，支持域名压缩指针编解码。
     *
     * 内存模型：所有字符串与容器均通过 PMR 分配器管理。
     *
     * @note id 字段默认为 0，调用方在发送前应自行设置。
     * @warning unpack 时若遇到域名压缩指针循环（跳转 > 255 次），
     *          将返回 std::nullopt。
     */
    class message
    {
    public:
        // --- Header 字段 ---

        std::uint16_t id{0};    // 报文标识
        bool qr{false};         // 0=查询, 1=响应
        std::uint8_t opcode{0}; // 操作码（0=标准查询）
        bool aa{false};         // 权威应答
        bool tc{false};         // 截断标志
        bool rd{false};         // 期望递归
        bool ra{false};         // 可用递归
        std::uint8_t rcode{0};  // 响应码

        // --- 各段 ---

        memory::vector<question> questions; // 查询段
        memory::vector<record> answers;     // 应答段
        memory::vector<record> authority;   // 权威段
        memory::vector<record> additional;  // 附加段

        /**
         * @brief 构造 DNS 报文
         * @param mr PMR 内存资源指针，默认使用当前全局资源
         */
        explicit message(memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 序列化为 DNS wire format
         * @return 完整的二进制报文字节序列
         * @details 按照如下顺序编码：12 字节 Header -> Question 列表 ->
         * Answer/Authority/Additional 记录列表。域名编码采用压缩指针优化。
         */
        [[nodiscard]] auto pack() const -> memory::vector<std::uint8_t>;

        /**
         * @brief 从二进制数据反序列化 DNS 报文
         * @param data 包含 DNS 报文的字节缓冲区
         * @param mr PMR 内存资源指针
         * @return 解析成功返回 message，否则返回 std::nullopt
         * @details 检查数据长度 >= 12，解析 Header 后逐段解码。
         * 域名解码时处理压缩指针并检测循环引用。
         */
        [[nodiscard]] static auto unpack(std::span<const std::uint8_t> data,
                                         memory::resource_pointer mr = memory::current_resource())
            -> std::optional<message>;

        /**
         * @brief 创建标准递归查询报文
         * @param domain 待查询域名（自动转小写并去除末尾点号）
         * @param qt 查询类型
         * @param mr PMR 内存资源指针
         * @return 构造好的查询 message
         * @details 设置 id=0, rd=true, opcode=0，添加一个 Question。
         */
        [[nodiscard]] static auto make_query(std::string_view domain, qtype qt,
                                             memory::resource_pointer mr = memory::current_resource())
            -> message;

        /**
         * @brief 提取所有 A/AAAA 记录的 IP 地址
         * @return 包含所有有效 IP 地址的列表（A 记录映射为 v4，AAAA 为 v6）
         */
        [[nodiscard]] auto extract_ips() const -> memory::vector<net::ip::address>;

        /**
         * @brief 计算所有记录中的最小 TTL
         * @return 所有段中记录的最小 TTL 值；若无任何记录则返回 0
         */
        [[nodiscard]] auto min_ttl() const -> std::uint32_t;

    private:
        memory::resource_pointer mr_;
    };

    // TCP 帧封装：2 字节大端长度前缀 + DNS 报文

    /**
     * @brief 将 DNS 报文封装为 TCP 帧格式
     * @param msg 待封装的 DNS 报文
     * @return {长度高字节, 长度低字节, ...报文字节}
     */
    [[nodiscard]] auto pack_tcp(const message &msg) -> memory::vector<std::uint8_t>;

    /**
     * @brief 从 TCP 帧中解析 DNS 报文
     * @param data 包含 TCP 帧的完整字节缓冲区
     * @param mr PMR 内存资源指针
     * @return 解析成功返回 message，否则返回 std::nullopt
     * @details 前 2 字节为大端长度前缀，其后为 DNS 报文主体。
     */
    [[nodiscard]] auto unpack_tcp(std::span<const std::uint8_t> data,
                                  memory::resource_pointer mr = memory::current_resource())
        -> std::optional<message>;

} // namespace ngx::resolve
