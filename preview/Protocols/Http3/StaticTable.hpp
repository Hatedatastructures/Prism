/**
 * @file StaticTable.hpp
 * @brief QPACK RFC 9204 静态表和编码查找表
 * @details 只保存编译期表数据与名称查找，不包含头块状态或动态表。
 *          当前 Preview QPACK 明确不启用动态表。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace Preview::Http3::Qpack::Detail
{

    /// QPACK 静态表条目
    struct StaticEntry
    {
        std::string_view Name;
        std::string_view value;
    };

    /// QPACK 静态表（RFC 9204 附录 A，99 项）
    inline constexpr std::array<StaticEntry, 99> StaticTable = {
        StaticEntry{":authority", ""},
        StaticEntry{":path", "/"},
        StaticEntry{"age", "0"},
        StaticEntry{"content-disposition", ""},
        StaticEntry{"content-length", "0"},
        StaticEntry{"cookie", ""},
        StaticEntry{"date", ""},
        StaticEntry{"etag", ""},
        StaticEntry{"if-modified-since", ""},
        StaticEntry{"if-none-match", ""},
        StaticEntry{"last-modified", ""},
        StaticEntry{"link", ""},
        StaticEntry{"location", ""},
        StaticEntry{"referer", ""},
        StaticEntry{"set-cookie", ""},
        StaticEntry{":method", "CONNECT"},
        StaticEntry{":method", "DELETE"},
        StaticEntry{":method", "GET"},
        StaticEntry{":method", "HEAD"},
        StaticEntry{":method", "OPTIONS"},
        StaticEntry{":method", "POST"},
        StaticEntry{":method", "PUT"},
        StaticEntry{":scheme", "http"},
        StaticEntry{":scheme", "https"},
        StaticEntry{":status", "103"},
        StaticEntry{":status", "200"},
        StaticEntry{":status", "304"},
        StaticEntry{":status", "404"},
        StaticEntry{":status", "503"},
        StaticEntry{"accept", "*/*"},
        StaticEntry{"accept", "application/dns-message"},
        StaticEntry{"accept-encoding", "gzip, deflate, br"},
        StaticEntry{"accept-ranges", "bytes"},
        StaticEntry{"access-control-allow-headers", "cache-control"},
        StaticEntry{"access-control-allow-headers", "content-type"},
        StaticEntry{"access-control-allow-origin", "*"},
        StaticEntry{"cache-control", "max-age=0"},
        StaticEntry{"cache-control", "max-age=2592000"},
        StaticEntry{"cache-control", "max-age=604800"},
        StaticEntry{"cache-control", "no-cache"},
        StaticEntry{"cache-control", "no-store"},
        StaticEntry{"cache-control", "public, max-age=31536000"},
        StaticEntry{"content-encoding", "br"},
        StaticEntry{"content-encoding", "gzip"},
        StaticEntry{"content-type", "application/dns-message"},
        StaticEntry{"content-type", "application/javascript"},
        StaticEntry{"content-type", "application/json"},
        StaticEntry{"content-type", "application/x-www-form-urlencoded"},
        StaticEntry{"content-type", "image/gif"},
        StaticEntry{"content-type", "image/jpeg"},
        StaticEntry{"content-type", "image/png"},
        StaticEntry{"content-type", "text/css"},
        StaticEntry{"content-type", "text/html; charset=utf-8"},
        StaticEntry{"content-type", "text/plain"},
        StaticEntry{"content-type", "text/plain;charset=utf-8"},
        StaticEntry{"range", "bytes=0-"},
        StaticEntry{"strict-transport-security", "max-age=31536000"},
        StaticEntry{"strict-transport-security", "max-age=31536000; includesubdomains"},
        StaticEntry{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
        StaticEntry{"vary", "accept-encoding"},
        StaticEntry{"vary", "origin"},
        StaticEntry{"x-content-type-options", "nosniff"},
        StaticEntry{"x-xss-protection", "1; mode=block"},
        StaticEntry{":status", "100"},
        StaticEntry{":status", "204"},
        StaticEntry{":status", "206"},
        StaticEntry{":status", "302"},
        StaticEntry{":status", "400"},
        StaticEntry{":status", "403"},
        StaticEntry{":status", "421"},
        StaticEntry{":status", "425"},
        StaticEntry{":status", "500"},
        StaticEntry{"accept-language", ""},
        StaticEntry{"access-control-allow-credentials", "FALSE"},
        StaticEntry{"access-control-allow-credentials", "TRUE"},
        StaticEntry{"access-control-allow-headers", "*"},
        StaticEntry{"access-control-allow-methods", "get"},
        StaticEntry{"access-control-allow-methods", "get, post, options"},
        StaticEntry{"access-control-allow-methods", "options"},
        StaticEntry{"access-control-expose-headers", "content-length"},
        StaticEntry{"access-control-request-headers", "content-type"},
        StaticEntry{"access-control-request-method", "get"},
        StaticEntry{"access-control-request-method", "post"},
        StaticEntry{"alt-svc", "clear"},
        StaticEntry{"authorization", ""},
        StaticEntry{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
        StaticEntry{"early-data", "1"},
        StaticEntry{"expect-ct", ""},
        StaticEntry{"forwarded", ""},
        StaticEntry{"if-range", ""},
        StaticEntry{"origin", ""},
        StaticEntry{"purpose", "prefetch"},
        StaticEntry{"server", ""},
        StaticEntry{"timing-allow-origin", "*"},
        StaticEntry{"upgrade-insecure-requests", "1"},
        StaticEntry{"user-agent", ""},
        StaticEntry{"x-forwarded-for", ""},
        StaticEntry{"x-frame-options", "deny"},
        StaticEntry{"x-frame-options", "sameorigin"},
    };

    /// HTTP/3 字段名必须遵守 RFC 9114 的全小写约束。
    constexpr auto ValidateStaticTableNames() -> bool
    {
        for (const auto &Entry : StaticTable)
        {
            for (const auto Character : Entry.Name)
            {
                if (Character >= 'A' && Character <= 'Z')
                {
                    return false;
                }
            }
        }
        return true;
    }

    static_assert(ValidateStaticTableNames(), "QPACK static table names must be lowercase");

    /// 编码器值条目（名称 → 值 → 静态表索引）
    struct EncoderValueEntry
    {
        std::string_view value;
        std::uint8_t index;
    };

    /// 编码器名称条目
    struct EncoderNameEntry
    {
        std::string_view Name;
        std::uint8_t FirstIndex;
        std::uint16_t ValueOffset;
        std::uint8_t ValueCount;
    };

    /// 编码器值条目表
    inline constexpr std::array<EncoderValueEntry, 78> EncoderValues = {
        EncoderValueEntry{"CONNECT", 15},
        EncoderValueEntry{"DELETE", 16},
        EncoderValueEntry{"GET", 17},
        EncoderValueEntry{"HEAD", 18},
        EncoderValueEntry{"OPTIONS", 19},
        EncoderValueEntry{"POST", 20},
        EncoderValueEntry{"PUT", 21},
        EncoderValueEntry{"/", 1},
        EncoderValueEntry{"103", 24},
        EncoderValueEntry{"200", 25},
        EncoderValueEntry{"304", 26},
        EncoderValueEntry{"404", 27},
        EncoderValueEntry{"503", 28},
        EncoderValueEntry{"100", 63},
        EncoderValueEntry{"204", 64},
        EncoderValueEntry{"206", 65},
        EncoderValueEntry{"302", 66},
        EncoderValueEntry{"400", 67},
        EncoderValueEntry{"403", 68},
        EncoderValueEntry{"421", 69},
        EncoderValueEntry{"425", 70},
        EncoderValueEntry{"500", 71},
        EncoderValueEntry{"http", 22},
        EncoderValueEntry{"https", 23},
        EncoderValueEntry{"0", 2},
        EncoderValueEntry{"0", 4},
        EncoderValueEntry{"*/*", 29},
        EncoderValueEntry{"application/dns-message", 30},
        EncoderValueEntry{"gzip, deflate, br", 31},
        EncoderValueEntry{"bytes", 32},
        EncoderValueEntry{"cache-control", 33},
        EncoderValueEntry{"content-type", 34},
        EncoderValueEntry{"*", 75},
        EncoderValueEntry{"*", 35},
        EncoderValueEntry{"max-age=0", 36},
        EncoderValueEntry{"max-age=2592000", 37},
        EncoderValueEntry{"max-age=604800", 38},
        EncoderValueEntry{"no-cache", 39},
        EncoderValueEntry{"no-store", 40},
        EncoderValueEntry{"public, max-age=31536000", 41},
        EncoderValueEntry{"br", 42},
        EncoderValueEntry{"gzip", 43},
        EncoderValueEntry{"application/dns-message", 44},
        EncoderValueEntry{"application/javascript", 45},
        EncoderValueEntry{"application/json", 46},
        EncoderValueEntry{"application/x-www-form-urlencoded", 47},
        EncoderValueEntry{"image/gif", 48},
        EncoderValueEntry{"image/jpeg", 49},
        EncoderValueEntry{"image/png", 50},
        EncoderValueEntry{"text/css", 51},
        EncoderValueEntry{"text/html; charset=utf-8", 52},
        EncoderValueEntry{"text/plain", 53},
        EncoderValueEntry{"text/plain;charset=utf-8", 54},
        EncoderValueEntry{"bytes=0-", 55},
        EncoderValueEntry{"max-age=31536000", 56},
        EncoderValueEntry{"max-age=31536000; includesubdomains", 57},
        EncoderValueEntry{"max-age=31536000; includesubdomains; preload", 58},
        EncoderValueEntry{"accept-encoding", 59},
        EncoderValueEntry{"origin", 60},
        EncoderValueEntry{"nosniff", 61},
        EncoderValueEntry{"1; mode=block", 62},
        EncoderValueEntry{"FALSE", 73},
        EncoderValueEntry{"TRUE", 74},
        EncoderValueEntry{"get", 76},
        EncoderValueEntry{"get, post, options", 77},
        EncoderValueEntry{"options", 78},
        EncoderValueEntry{"content-length", 79},
        EncoderValueEntry{"content-type", 80},
        EncoderValueEntry{"get", 81},
        EncoderValueEntry{"post", 82},
        EncoderValueEntry{"clear", 83},
        EncoderValueEntry{"script-src 'none'; object-src 'none'; base-uri 'none'", 85},
        EncoderValueEntry{"1", 86},
        EncoderValueEntry{"prefetch", 91},
        EncoderValueEntry{"*", 93},
        EncoderValueEntry{"1", 94},
        EncoderValueEntry{"deny", 97},
        EncoderValueEntry{"sameorigin", 98},
    };

    /// 编码器名称表
    inline constexpr std::array<EncoderNameEntry, 52> EncoderNames = {
        EncoderNameEntry{":method", 15, 0, 7},
        EncoderNameEntry{":path", 1, 7, 1},
        EncoderNameEntry{":status", 24, 8, 14},
        EncoderNameEntry{":scheme", 22, 22, 2},
        EncoderNameEntry{":authority", 0, 24, 0},
        EncoderNameEntry{"age", 2, 24, 1},
        EncoderNameEntry{"content-disposition", 3, 25, 0},
        EncoderNameEntry{"content-length", 4, 25, 1},
        EncoderNameEntry{"cookie", 5, 26, 0},
        EncoderNameEntry{"date", 6, 26, 0},
        EncoderNameEntry{"etag", 7, 26, 0},
        EncoderNameEntry{"if-modified-since", 8, 26, 0},
        EncoderNameEntry{"if-none-match", 9, 26, 0},
        EncoderNameEntry{"last-modified", 10, 26, 0},
        EncoderNameEntry{"link", 11, 26, 0},
        EncoderNameEntry{"location", 12, 26, 0},
        EncoderNameEntry{"referer", 13, 26, 0},
        EncoderNameEntry{"set-cookie", 14, 26, 0},
        EncoderNameEntry{"accept", 29, 26, 2},
        EncoderNameEntry{"accept-encoding", 31, 28, 1},
        EncoderNameEntry{"accept-ranges", 32, 29, 1},
        EncoderNameEntry{"access-control-allow-headers", 33, 30, 3},
        EncoderNameEntry{"access-control-allow-origin", 35, 33, 1},
        EncoderNameEntry{"cache-control", 36, 34, 6},
        EncoderNameEntry{"content-encoding", 42, 40, 2},
        EncoderNameEntry{"content-type", 44, 42, 11},
        EncoderNameEntry{"range", 55, 53, 1},
        EncoderNameEntry{"strict-transport-security", 56, 54, 3},
        EncoderNameEntry{"vary", 59, 57, 2},
        EncoderNameEntry{"x-content-type-options", 61, 59, 1},
        EncoderNameEntry{"x-xss-protection", 62, 60, 1},
        EncoderNameEntry{"accept-language", 72, 61, 0},
        EncoderNameEntry{"access-control-allow-credentials", 73, 61, 2},
        EncoderNameEntry{"access-control-allow-methods", 76, 63, 3},
        EncoderNameEntry{"access-control-expose-headers", 79, 66, 1},
        EncoderNameEntry{"access-control-request-headers", 80, 67, 1},
        EncoderNameEntry{"access-control-request-method", 81, 68, 2},
        EncoderNameEntry{"alt-svc", 83, 70, 1},
        EncoderNameEntry{"authorization", 84, 71, 0},
        EncoderNameEntry{"content-security-policy", 85, 71, 1},
        EncoderNameEntry{"early-data", 86, 72, 1},
        EncoderNameEntry{"expect-ct", 87, 73, 0},
        EncoderNameEntry{"forwarded", 88, 73, 0},
        EncoderNameEntry{"if-range", 89, 73, 0},
        EncoderNameEntry{"origin", 90, 73, 0},
        EncoderNameEntry{"purpose", 91, 73, 1},
        EncoderNameEntry{"server", 92, 74, 0},
        EncoderNameEntry{"timing-allow-origin", 93, 74, 1},
        EncoderNameEntry{"upgrade-insecure-requests", 94, 75, 1},
        EncoderNameEntry{"user-agent", 95, 76, 0},
        EncoderNameEntry{"x-forwarded-for", 96, 76, 0},
        EncoderNameEntry{"x-frame-options", 97, 76, 2},
    };

    /// 编译期校验编码表与静态表语义一致
    constexpr auto ValidateEncoderTables() -> bool
    {
        for (const auto &Entry : EncoderNames)
        {
            if (StaticTable[Entry.FirstIndex].Name != Entry.Name)
            {
                return false;
            }
            for (std::size_t I = 0; I < Entry.ValueCount; ++I)
            {
                const auto &Value = EncoderValues[Entry.ValueOffset + I];
                if (StaticTable[Value.index].Name != Entry.Name || StaticTable[Value.index].value != Value.value)
                {
                    return false;
                }
            }
        }
        return true;
    }

    static_assert(ValidateEncoderTables(), "encoder 表与静态表不一致");

    /**
     * @brief 静态表名称查找
     * @param Name 字段名
     * @return 名称条目指针；未命中返回 nullptr
     */
    [[nodiscard]] inline auto LookupEncoderName(std::string_view Name) -> const EncoderNameEntry *
    {
        for (const auto &Entry : EncoderNames)
        {
            if (Entry.Name == Name)
            {
                return &Entry;
            }
        }
        return nullptr;
    }

} // namespace Preview::Http3::Qpack::Detail
