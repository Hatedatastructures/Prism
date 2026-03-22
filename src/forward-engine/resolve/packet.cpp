#include <forward-engine/resolve/packet.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/trace.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <unordered_map>
#include <utility>

namespace ngx::resolve
{

    // 辅助：大端读写

    namespace
    {
        /**
         * @brief 向缓冲区写入 16 位大端整数
         */
        void write_u16_be(memory::vector<std::uint8_t> &buf, const std::size_t offset, const std::uint16_t value)
        {
            buf[offset] = static_cast<std::uint8_t>(value >> 8);
            buf[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
        }

        /**
         * @brief 向缓冲区写入 32 位大端整数
         */
        void write_u32_be(memory::vector<std::uint8_t> &buf, const std::size_t offset, const std::uint32_t value)
        {
            buf[offset] = static_cast<std::uint8_t>(value >> 24);
            buf[offset + 1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
            buf[offset + 2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
            buf[offset + 3] = static_cast<std::uint8_t>(value & 0xFF);
        }

        /**
         * @brief 从缓冲区读取 16 位大端整数
         */
        [[nodiscard]] auto read_u16_be(const std::span<const std::uint8_t> data, const std::size_t offset) -> std::uint16_t
        {
            return (static_cast<std::uint16_t>(data[offset]) << 8) | static_cast<std::uint16_t>(data[offset + 1]);
        }

        /**
         * @brief 从缓冲区读取 32 位大端整数
         */
        [[nodiscard]] auto read_u32_be(const std::span<const std::uint8_t> data, const std::size_t offset) -> std::uint32_t
        {
            return (static_cast<std::uint32_t>(data[offset]) << 24) | (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
                   (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
                   static_cast<std::uint32_t>(data[offset + 3]);
        }

        /**
         * @brief 将域名转换为小写并去除末尾点号
         * @param domain 原始域名
         * @return 处理后的域名 string_view（引用同一缓冲区，不做拷贝）
         * @note 调用方需保证原始域名在返回值使用期间有效
         */
        [[nodiscard]] auto normalize_domain(const std::string_view domain) -> std::string_view
        {
            auto trimmed = domain;
            if (!trimmed.empty() && trimmed.back() == '.')
            {
                trimmed.remove_suffix(1);
            }
            return trimmed;
        }

        /**
         * @brief 将域名转为小写 PMR string（去除末尾点号）
         */
        [[nodiscard]] auto to_lower_domain(const std::string_view domain, memory::resource_pointer mr) -> memory::string
        {
            const auto trimmed = normalize_domain(domain);
            memory::string result(trimmed.size(), '\0', mr);
            for (std::size_t i = 0; i < trimmed.size(); ++i)
            {
                result[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(trimmed[i])));
            }
            return result;
        }

        // 域名编码（压缩指针）

        /**
         * @brief 编码单个域名到缓冲区，使用压缩指针优化
         * @param domain 待编码域名（小写无末尾点号的 dotted 格式）
         * @param buf 目标缓冲区
         * @param pos 当前写入位置（传入时为域名标签起始偏移）
         * @param compression 压缩映射表（域名后缀 -> 偏移量）
         * @return 编码完成后的新写入位置
         *```
         * 算法：从最长后缀开始查找压缩机会。
         * 例如 "www.example.com" 依次尝试：
         *   "www.example.com" -> 未命中
         *   "example.com"      -> 未命中，登记偏移
         *   "com"              -> 未命中，登记偏移
         * 全部未命中则按标签逐段写入；若某后缀命中则写入压缩指针。
         * ````
         */
        [[nodiscard]] auto encode_name(const std::string_view domain, memory::vector<std::uint8_t> &buf,
                                       std::size_t pos, std::unordered_map<std::string_view, std::uint16_t> &compression)
            -> std::size_t
        {
            // 逐段写入域名标签，逐标签检查压缩机会
            // 例如 "www.example.com" 依次尝试匹配：
            //   "www.example.com" -> 未命中，写入标签 "www"，登记此位置
            //   "example.com"      -> 未命中，写入标签 "example"，登记此位置
            //   "com"              -> 未命中，写入标签 "com"，登记此位置
            // 若某后缀命中则直接写入 2 字节压缩指针，跳过后续标签
            std::size_t p = 0;
            while (p < domain.size())
            {
                const auto dot = domain.find('.', p);
                const std::string_view label = (dot == std::string_view::npos) ? domain.substr(p) : domain.substr(p, dot - p);

                // 检查从当前位置开始的后缀是否已在压缩表中
                const auto suffix_from_here = domain.substr(p);
                if (const auto it = compression.find(suffix_from_here); it != compression.end())
                {
                    // 写入压缩指针：0xC0 | offset
                    const auto ptr = static_cast<std::uint16_t>(0xC000u | it->second);
                    buf.push_back(static_cast<std::uint8_t>(ptr >> 8));
                    buf.push_back(static_cast<std::uint8_t>(ptr & 0xFF));
                    return buf.size();
                }

                // 未命中，写入普通标签：长度 + 内容
                buf.push_back(static_cast<std::uint8_t>(label.size()));
                for (const char c : label)
                {
                    buf.push_back(static_cast<std::uint8_t>(c));
                }

                // 将此位置（域名后缀的起始偏移）登记到压缩表
                compression[suffix_from_here] = static_cast<std::uint16_t>(pos);
                pos = buf.size();

                if (dot == std::string_view::npos)
                {
                    break;
                }
                p = dot + 1;
            }

            // 写入域名结束标记 0x00
            buf.push_back(0x00);
            return buf.size();
        }

        /**
         * @brief 解码 DNS 域名（wire format -> dotted 格式）
         * @param data 完整 DNS 报文缓冲区
         * @param offset 域名起始偏移（输入/输出参数）
         @param jumps 压缩指针跳转计数（用于检测循环）
         * @return 解码后的域名 string_view（引用原始缓冲区数据）
         *
         * 算法：
         * - < 0xC0: 普通标签，读长度 + 内容
         * - >= 0xC0: 压缩指针，低 14 位为偏移量，递归跳转
         * - 跳转计数 > 255 视为循环，返回空 string_view
         */
        [[nodiscard]] auto decode_name_raw(const std::span<const std::uint8_t> data,
                                           std::size_t &offset, std::size_t &jumps)
            -> std::string_view
        {
            // 使用栈上小缓冲区拼接域名标签，避免中间分配
            // DNS 域名最大 253 字节，加上分隔符足够
            std::array<char, 256> name_buf{};
            std::size_t name_len = 0;

            std::size_t pos = offset;
            bool jumped = false;
            std::size_t saved_offset = 0; // 记录第一个跳转点前的位置，用于更新 offset

            while (true)
            {
                if (pos >= data.size())
                {
                    return {};
                }

                const auto len = data[pos];

                if (len == 0)
                {
                    // 域名结束标记
                    if (!jumped)
                    {
                        offset = pos + 1;
                    }
                    break;
                }

                if ((len & 0xC0) == 0xC0)
                {
                    // 压缩指针
                    if (pos + 1 >= data.size())
                    {
                        return {};
                    }

                    ++jumps;
                    if (jumps > 255)
                    {
                        trace::warn("[Resolve] domain name compression pointer loop detected");
                        return {};
                    }

                    if (!jumped)
                    {
                        saved_offset = pos + 2;
                        jumped = true;
                    }

                    const auto ptr = (static_cast<std::uint16_t>(data[pos] & 0x3F) << 8) | static_cast<std::uint16_t>(data[pos + 1]);
                    pos = ptr;
                }
                else if ((len & 0xC0) == 0)
                {
                    // 普通标签
                    ++pos;
                    if (pos + len > data.size())
                    {
                        return {};
                    }

                    if (name_len > 0 && name_len < name_buf.size())
                    {
                        name_buf[name_len++] = '.';
                    }

                    for (std::size_t i = 0; i < len && name_len < name_buf.size(); ++i)
                    {
                        name_buf[name_len++] = static_cast<char>(std::tolower(data[pos + i]));
                    }

                    pos += len;
                }
                else
                {
                    // 保留标签类型（0x40/0x80），不支持
                    trace::warn("[Resolve] unsupported label type 0x{:02X}", static_cast<unsigned>(len));
                    return {};
                }
            }

            if (jumped)
            {
                offset = saved_offset;
            }

            // 去除末尾可能残留的点号
            if (name_len > 0 && name_buf[name_len - 1] == '.')
            {
                --name_len;
            }

            // 拷贝到临时 std::string（decode_name 调用方会再转为 PMR string）
            static thread_local std::string tls_buf;
            tls_buf.assign(name_buf.data(), name_len);
            return std::string_view(tls_buf);
        }

        /**
         * @brief 解码 DNS 域名并返回 PMR string
         * @param data 完整 DNS 报文缓冲区
         * @param offset 域名起始偏移（输入/输出参数）
         * @param jumps 压缩指针跳转计数
         * @param mr PMR 内存资源指针
         * @return 解码后的 PMR string；解码失败时返回空字符串
         */
        [[nodiscard]] auto decode_name(const std::span<const std::uint8_t> data,
                                       std::size_t &offset, std::size_t &jumps, memory::resource_pointer mr)
            -> memory::string
        {
            const auto sv = decode_name_raw(data, offset, jumps);
            if (sv.empty())
            {
                return memory::string{mr};
            }
            return memory::string{sv, mr};
        }

    } // anonymous namespace

    // 工具函数实现

    auto extract_ipv4(const record &rec) -> std::optional<net::ip::address_v4>
    {
        if (rec.type != qtype::a || rec.rdata.size() != 4)
        {
            return std::nullopt;
        }

        const auto bytes = rec.rdata.data();
        const auto addr = net::ip::address_v4(
            (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
            (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]));

        return addr;
    }

    auto extract_ipv6(const record &rec) -> std::optional<net::ip::address_v6>
    {
        if (rec.type != qtype::aaaa || rec.rdata.size() != 16)
        {
            return std::nullopt;
        }

        net::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), rec.rdata.data(), 16);

        return net::ip::address_v6{bytes};
    }

    // message 实现

    message::message(const memory::resource_pointer mr)
        : questions(mr), answers(mr), authority(mr), additional(mr), mr_(mr ? mr : memory::current_resource())
    {
    }

    auto message::pack() const -> memory::vector<std::uint8_t>
    {
        // 预分配 512 字节（DNS 传统最大报文长度），减少 realloc
        memory::vector<std::uint8_t> buf(512, mr_);
        buf.resize(12); // 先占位 12 字节 Header

        // 构建压缩表（使用 string_view 键，指向 message 内的 name 字符串）
        std::unordered_map<std::string_view, std::uint16_t> compression;

        // ---- 编码 Header ----
        // 位移布局：ID(0-1) FLAGS(2-3) QD(4-5) AN(6-7) NS(8-9) AR(10-11)
        write_u16_be(buf, 0, id);

        // FLAGS: QR(1bit) OPCODE(4bit) AA(1bit) TC(1bit) RD(1bit) RA(1bit) Z(3bit) RCODE(4bit)
        const auto flags = static_cast<std::uint16_t>(
            (qr ? 0x8000u : 0u) |
            ((static_cast<std::uint16_t>(opcode) & 0x0Fu) << 11) |
            (aa ? 0x0400u : 0u) | (tc ? 0x0200u : 0u) |
            (rd ? 0x0100u : 0u) | (ra ? 0x0080u : 0u) |
            (static_cast<std::uint16_t>(rcode) & 0x0Fu));

        write_u16_be(buf, 2, flags);
        write_u16_be(buf, 4, static_cast<std::uint16_t>(questions.size()));
        write_u16_be(buf, 6, static_cast<std::uint16_t>(answers.size()));
        write_u16_be(buf, 8, static_cast<std::uint16_t>(authority.size()));
        write_u16_be(buf, 10, static_cast<std::uint16_t>(additional.size()));

        // ---- 编码 Question 段 ----
        for (const auto &q : questions)
        {
            (void)encode_name(q.name, buf, buf.size(), compression);
            buf.push_back(static_cast<std::uint8_t>(static_cast<std::uint16_t>(q.qtype) >> 8));
            buf.push_back(static_cast<std::uint8_t>(static_cast<std::uint16_t>(q.qtype) & 0xFF));
            buf.push_back(static_cast<std::uint8_t>(q.qclass >> 8));
            buf.push_back(static_cast<std::uint8_t>(q.qclass & 0xFF));
        }

        // ---- 编码 Record 段（Answer / Authority / Additional 共用逻辑） ----
        const auto encode_records = [&](const memory::vector<record> &records)
        {
            for (const auto &r : records)
            {
                // NAME（复用压缩表）
                (void)encode_name(r.name, buf, buf.size(), compression);

                // TYPE (16 bit)
                buf.push_back(static_cast<std::uint8_t>(static_cast<std::uint16_t>(r.type) >> 8));
                buf.push_back(static_cast<std::uint8_t>(static_cast<std::uint16_t>(r.type) & 0xFF));

                // CLASS (16 bit)
                buf.push_back(static_cast<std::uint8_t>(r.rclass >> 8));
                buf.push_back(static_cast<std::uint8_t>(r.rclass & 0xFF));

                // TTL (32 bit)
                buf.push_back(static_cast<std::uint8_t>(r.ttl >> 24));
                buf.push_back(static_cast<std::uint8_t>((r.ttl >> 16) & 0xFF));
                buf.push_back(static_cast<std::uint8_t>((r.ttl >> 8) & 0xFF));
                buf.push_back(static_cast<std::uint8_t>(r.ttl & 0xFF));

                // RDLENGTH (16 bit) + RDATA
                const auto rdlen = static_cast<std::uint16_t>(r.rdata.size());
                buf.push_back(static_cast<std::uint8_t>(rdlen >> 8));
                buf.push_back(static_cast<std::uint8_t>(rdlen & 0xFF));
                buf.insert(buf.end(), r.rdata.begin(), r.rdata.end());
            }
        };

        encode_records(answers);
        encode_records(authority);
        encode_records(additional);

        trace::debug("[Resolve] {} bytes, {}Q {}A {}NS {}AR",
                     buf.size(), questions.size(), answers.size(), authority.size(), additional.size());

        return buf;
    }

    auto message::unpack(const std::span<const std::uint8_t> data, const memory::resource_pointer mr)
        -> std::optional<message>
    {
        if (data.size() < 12)
        {
            trace::warn("[Resolve] data too short ({} bytes)", data.size());
            return std::nullopt;
        }

        message msg(mr ? mr : memory::current_resource());

        // ---- 解析 Header ----
        msg.id = read_u16_be(data, 0);
        const auto flags = read_u16_be(data, 2);
        msg.qr = (flags & 0x8000u) != 0;
        msg.opcode = static_cast<std::uint8_t>((flags >> 11) & 0x0F);
        msg.aa = (flags & 0x0400u) != 0;
        msg.tc = (flags & 0x0200u) != 0;
        msg.rd = (flags & 0x0100u) != 0;
        msg.ra = (flags & 0x0080u) != 0;
        msg.rcode = static_cast<std::uint8_t>(flags & 0x0F);

        const auto qdcount = read_u16_be(data, 4);
        const auto ancount = read_u16_be(data, 6);
        const auto nscount = read_u16_be(data, 8);
        const auto arcount = read_u16_be(data, 10);

        std::size_t offset = 12;
        std::size_t jumps = 0;

        // ---- 解析 Question 段 ----
        for (std::uint16_t i = 0; i < qdcount; ++i)
        {
            question q(msg.mr_);

            q.name = decode_name(data, offset, jumps, msg.mr_);
            if (q.name.empty() && offset >= data.size())
            {
                trace::warn("[Resolve] Question #{} domain decode failed", i);
                return std::nullopt;
            }

            if (offset + 4 > data.size())
            {
                trace::warn("[Resolve] Question #{} data insufficient", i);
                return std::nullopt;
            }

            q.qtype = static_cast<qtype>(read_u16_be(data, offset));
            q.qclass = read_u16_be(data, offset + 2);
            offset += 4;

            msg.questions.push_back(std::move(q));
        }

        // ---- 解析 Record 段的通用 lambda ----
        const auto parse_records = [&](const std::uint16_t count, memory::vector<record> &records) -> bool
        {
            for (std::uint16_t i = 0; i < count; ++i)
            {
                record r(msg.mr_);

                r.name = decode_name(data, offset, jumps, msg.mr_);
                if (r.name.empty() && offset >= data.size())
                {
                    trace::warn("[Resolve] Record #{} domain decode failed", i);
                    return false;
                }

                // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 字节
                if (offset + 10 > data.size())
                {
                    trace::warn("[Resolve] Record #{} header data insufficient", i);
                    return false;
                }

                r.type = static_cast<qtype>(read_u16_be(data, offset));
                r.rclass = read_u16_be(data, offset + 2);
                r.ttl = read_u32_be(data, offset + 4);
                const auto rdlength = read_u16_be(data, offset + 8);
                offset += 10;

                if (offset + rdlength > data.size())
                {
                    trace::warn("[Resolve] Record #{} rdata out of bounds (need {}, remaining {})",
                                i, rdlength, data.size() - offset);
                    return false;
                }

                r.rdata.assign(data.begin() + static_cast<std::ptrdiff_t>(offset),
                               data.begin() + static_cast<std::ptrdiff_t>(offset + rdlength));
                offset += rdlength;

                records.push_back(std::move(r));
            }
            return true;
        };

        if (!parse_records(ancount, msg.answers))
        {
            return std::nullopt;
        }
        if (!parse_records(nscount, msg.authority))
        {
            return std::nullopt;
        }
        if (!parse_records(arcount, msg.additional))
        {
            return std::nullopt;
        }

        trace::debug("[Resolve] {} bytes -> {}Q {}A {}NS {}AR",
                     data.size(), qdcount, ancount, nscount, arcount);

        return msg;
    }

    auto message::make_query(const std::string_view domain, const qtype qt, const memory::resource_pointer mr)
        -> message
    {
        message msg(mr ? mr : memory::current_resource());

        msg.id = 0;
        msg.rd = true;
        msg.opcode = 0;

        question q(msg.mr_);
        q.name = to_lower_domain(domain, msg.mr_);
        q.qtype = qt;
        q.qclass = 1; // IN

        msg.questions.push_back(std::move(q));

        return msg;
    }

    auto message::extract_ips() const -> memory::vector<net::ip::address>
    {
        memory::vector<net::ip::address> ips(mr_);

        const auto collect = [&](const memory::vector<record> &records)
        {
            for (const auto &r : records)
            {
                if (r.type == qtype::a)
                {
                    if (const auto v4 = extract_ipv4(r))
                    {
                        ips.push_back(net::ip::address{*v4});
                    }
                }
                else if (r.type == qtype::aaaa)
                {
                    if (const auto v6 = extract_ipv6(r))
                    {
                        ips.push_back(net::ip::address{*v6});
                    }
                }
            }
        };

        collect(answers);
        collect(authority);
        collect(additional);

        return ips;
    }

    auto message::min_ttl() const -> std::uint32_t
    {
        std::uint32_t result = std::numeric_limits<std::uint32_t>::max();
        bool found = false;

        const auto check = [&](const memory::vector<record> &records)
        {
            for (const auto &r : records)
            {
                if (r.ttl < result)
                {
                    result = r.ttl;
                    found = true;
                }
            }
        };

        check(answers);
        check(authority);
        check(additional);

        return found ? result : 0;
    }

    auto unpack_tcp(const std::span<const std::uint8_t> data, const memory::resource_pointer mr)
        -> std::optional<message>
    {
        if (data.size() < 2)
        {
            trace::warn("[Resolve] data too short for TCP length prefix ({} bytes)", data.size());
            return std::nullopt;
        }

        const auto length = (static_cast<std::uint16_t>(data[0]) << 8) | static_cast<std::uint16_t>(data[1]);

        if (data.size() < 2 + static_cast<std::size_t>(length))
        {
            trace::warn("[Resolve] incomplete message (declared {} bytes, got {})",
                        length, data.size() - 2);
            return std::nullopt;
        }

        return message::unpack(data.subspan(2, length), mr);
    }

} // namespace ngx::resolve
