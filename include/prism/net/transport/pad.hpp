/**
 * @file pad.hpp
 * @brief Transport 层记录填充装饰器
 * @details 在 async_write_some 中根据填充策略注入随机填充字节,
 *          混淆 tunnel relay 的字节流大小特征。使用 BLAKE3 作为
 *          CSPRNG 生成随机填充大小和内容。
 *          前 stop_after 次 write 执行填充,之后透传零开销。
 */

#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <span>

#include <blake3.h>

namespace psm::transport
{

    namespace net = boost::asio;

    /**
     * @struct pad_target
     * @brief 填充目标描述
     * @details 用 [min_val, max_val] 区间描述单条填充目标记录。
     */
    struct pad_target
    {
        std::uint16_t min_val{0}; // 填充长度下限
        std::uint16_t max_val{0}; // 填充长度上限
    };

    /**
     * @struct pad_config
     * @brief 填充配置
     */
    struct pad_config
    {
        memory::string pad_targets{"17,30-50,30-50,80-150"}; // 填充目标规格（逗号分隔，区间用 "-" 连接）
        std::uint8_t stop_after{12};                         // 前 N 次写入执行填充
        std::uint16_t max_pad_bytes{256};                    // 单次填充字节数上限

        /**
         * @brief 填充功能是否启用
         * @return pad_targets 非空返回 true
         */
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !pad_targets.empty();
        }
    };

    /**
     * @class pad_transport
     * @brief Transport 层记录填充装饰器
     * @details 包装下层传输,在前 N 次 write 中注入随机填充。
     *          读操作直接透传。使用 BLAKE3 CTR 模式作为 CSPRNG。
     */
    class pad_transport final : public transmission
    {
    public:
        /**
         * @brief 构造填充装饰器
         * @param inner 被包装的内层传输
         * @param cfg 填充配置
         */
        explicit pad_transport(shared_transmission inner, const pad_config &cfg);

        ~pad_transport() noexcept override = default;

        /**
         * @brief 获取传输层类型
         * @return 内层传输的类型
         */
        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return inner_->transport_type();
        }

        /**
         * @brief 获取内层传输
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return inner_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return inner_.get();
        }

        /**
         * @brief 获取关联的执行器
         * @return 内层传输的执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override
        {
            return inner_->executor();
        }

        /**
         * @brief 异步读取数据
         * @details 读操作直接透传给内层传输，不做填充处理。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 在前 stop_after 次写入中按填充策略注入随机填充，
         * 之后透传零开销。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         */
        void close() override;

        /**
         * @brief 取消所有未完成的异步操作
         */
        void cancel() override;

    private:
        shared_transmission inner_;                    // 被包装的内层传输
        pad_config cfg_;                               // 填充配置
        memory::vector<pad_target> targets_;           // 解析后的填充目标列表
        memory::vector<std::byte> pad_buf_;            // 填充数据缓冲区
        std::uint8_t write_count_{0};                  // 已执行填充的写入次数

        /// BLAKE3 CSPRNG 状态
        std::array<std::uint8_t, 32> rng_key_{};       // CSPRNG 密钥
        std::uint64_t rng_counter_{0};                 // CSPRNG 计数器
        std::array<std::uint8_t, 32> rng_cache_{};     // CSPRNG 输出缓存
        std::size_t rng_cache_pos_{32};                // CSPRNG 缓存读取位置

        /**
         * @brief 计算当前 write 的填充字节数
         * @param data_len 待写入的数据长度
         * @return 本次写入的填充字节数
         */
        [[nodiscard]] auto compute_padding(std::size_t data_len) -> std::size_t;

        /**
         * @brief 从 CSPRNG 生成 [min_val, max_val] 范围的随机数
         * @param min_val 随机数下限
         * @param max_val 随机数上限
         * @return [min_val, max_val] 范围内的随机数
         */
        [[nodiscard]] auto rng_next_u16(std::uint16_t min_val, std::uint16_t max_val) -> std::uint16_t;

        /**
         * @brief 刷新 CSPRNG 缓存
         */
        auto rng_refill() -> void;

        /**
         * @brief 从 CSPRNG 填充指定缓冲区
         * @param out 目标缓冲区
         */
        auto rng_next_bytes(std::span<std::byte> out) -> void;

        /**
         * @brief 解析 pad_targets 字符串为目标列表
         * @param spec 填充目标规格字符串
         * @param mr 内存资源指针
         * @return 解析后的填充目标列表
         */
        [[nodiscard]] static auto parse_targets(std::string_view spec, memory::resource_pointer mr)
            -> memory::vector<pad_target>;
    };

} // namespace psm::transport
