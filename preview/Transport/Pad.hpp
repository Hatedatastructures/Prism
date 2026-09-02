/**
 * @file Pad.hpp
 * @brief Transport 层记录填充装饰器
 * @details 在 async_write_some 中根据填充策略注入随机填充字节,
 *          混淆 tunnel relay 的字节流大小特征。使用 BLAKE3 作为
 *          CSPRNG 生成随机填充大小和内容。
 *          前 StopAfter 次 Write 执行填充,之后透传零开销。
 */

#pragma once

#include <openssl/rand.h>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Transport/Transmission.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <span>

#include <blake3.h>

namespace Preview::Transport {


    namespace net = boost::asio;

    /**
     * @struct PadTarget
     * @brief 填充目标描述
     * @details 用 [MinVal, MaxVal] 区间描述单条填充目标记录。
     */
    struct PadTarget
    {
        std::uint16_t MinVal{0}; // 填充长度下限
        std::uint16_t MaxVal{0}; // 填充长度上限
    };

    /**
     * @struct PadConfig
     * @brief 填充配置
     */
    struct PadConfig
    {
        std::string PadTargets{"17,30-50,30-50,80-150"}; // 填充目标规格（逗号分隔，区间用 "-" 连接）
        std::uint8_t StopAfter{12};                         // 前 N 次写入执行填充
        std::uint16_t MaxPadBytes{256};                    // 单次填充字节数上限

        /**
         * @brief 填充功能是否启用
         * @return PadTargets 非空返回 true
         */
        [[nodiscard]] auto Enabled() const noexcept -> bool
        {
            return !PadTargets.empty();
        }
    };

    /**
     * @class PadTransport
     * @brief Transport 层记录填充装饰器
     * @details 包装下层传输,在前 N 次 Write 中注入随机填充。
     *          读操作直接透传。使用 BLAKE3 CTR 模式作为 CSPRNG。
     */
    class PadTransport final : public Transmission
    {
    public:
        /**
         * @brief 构造填充装饰器
         * @param Inner 被包装的内层传输
         * @param cfg 填充配置
         */
        explicit PadTransport(SharedTransmission Inner, const PadConfig &cfg);

        ~PadTransport() noexcept override = default;

        /**
         * @brief 获取传输层类型
         * @return 内层传输的类型
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Inner_->TransportType();
        }

        /**
         * @brief 获取内层传输
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return Inner_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return Inner_.get();
        }

        /**
         * @brief 获取关联的执行器
         * @return 内层传输的执行器
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        /**
         * @brief 异步读取数据
         * @details 读操作直接透传给内层传输，不做填充处理。
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 在前 StopAfter 次写入中按填充策略注入随机填充，
         * 之后透传零开销。
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         */
        void Close() override;

        /**
         * @brief 取消所有未完成的异步操作
         */
        void Cancel() override;

    private:
        SharedTransmission Inner_;                    // 被包装的内层传输
        PadConfig Cfg_;                               // 填充配置
        Preview::Memory::Vector<PadTarget> Targets_;           // 解析后的填充目标列表
        Preview::Memory::Vector<std::byte> PadBuf_;            // 填充数据缓冲区
        std::uint8_t WriteCount_{0};                  // 已执行填充的写入次数

        /// BLAKE3 CSPRNG 状态
        std::array<std::uint8_t, 32> RngKey_{};       // CSPRNG 密钥
        std::uint64_t RngCounter_{0};                 // CSPRNG 计数器
        std::array<std::uint8_t, 32> RngCache_{};     // CSPRNG 输出缓存
        std::size_t RngCachePos_{32};                // CSPRNG 缓存读取位置

        /**
         * @brief 计算当前 Write 的填充字节数
         * @param DataLen 待写入的数据长度
         * @return 本次写入的填充字节数
         */
        [[nodiscard]] auto ComputePadding(std::size_t DataLen) -> std::size_t;

        /**
         * @brief 从 CSPRNG 生成 [MinVal, MaxVal] 范围的随机数
         * @param MinVal 随机数下限
         * @param MaxVal 随机数上限
         * @return [MinVal, MaxVal] 范围内的随机数
         */
        [[nodiscard]] auto RngNextU16(std::uint16_t MinVal, std::uint16_t MaxVal) -> std::uint16_t;

        /**
         * @brief 刷新 CSPRNG 缓存
         */
        auto RngRefill() -> void;

        /**
         * @brief 从 CSPRNG 填充指定缓冲区
         * @param out 目标缓冲区
         */
        auto RngNextBytes(std::span<std::byte> out) -> void;

        /**
         * @brief 解析 PadTargets 字符串为目标列表
         * @param spec 填充目标规格字符串
         * @param mr 内存资源指针
         * @return 解析后的填充目标列表
         */
        [[nodiscard]] static auto ParseTargets(std::string_view spec, Preview::Memory::ResourcePointer mr)
            -> Preview::Memory::Vector<PadTarget>;
    };




    inline PadTransport::PadTransport(SharedTransmission Inner, const PadConfig &cfg)
        : Inner_(std::move(Inner)), Cfg_(cfg),
          Targets_(ParseTargets(cfg.PadTargets, Preview::Memory::CurrentResource())),
          PadBuf_(16384 + 256, Preview::Memory::CurrentResource())
    {
        /// 从 BoringSSL 获取 CSPRNG 种子
        RAND_bytes(RngKey_.data(), static_cast<int>(RngKey_.size()));
    }

    inline auto PadTransport::async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await Inner_->async_read_some(Buffer, ec);
    }

    inline auto PadTransport::async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        /// 未启用或超过 StopAfter 后直接透传,零开销
        if (!Cfg_.Enabled() || WriteCount_ >= Cfg_.StopAfter || Buffer.empty())
        {
            co_return co_await Inner_->async_write_some(Buffer, ec);
        }

        const auto DataLen = Buffer.size();
        const auto PadSize = ComputePadding(DataLen);
        const auto Total = DataLen + PadSize;

        /// 如果 PadBuf_ 不够大,直接透传(极端情况)
        if (Total > PadBuf_.size())
        {
            co_return co_await Inner_->async_write_some(Buffer, ec);
        }

        std::memcpy(PadBuf_.data(), Buffer.data(), DataLen);
        if (PadSize > 0)
        {
            RngNextBytes(std::span<std::byte>(PadBuf_.data() + DataLen, PadSize));
        }

        co_await Inner_->AsyncWrite(std::span<const std::byte>(PadBuf_.data(), Total), ec);

        ++WriteCount_;

        if (ec)
        {
            co_return 0;
        }
        co_return DataLen;
    }

    inline void PadTransport::Close()
    {
        Inner_->Close();
    }

    inline void PadTransport::Cancel()
    {
        Inner_->Cancel();
    }

    inline auto PadTransport::ComputePadding(std::size_t DataLen) -> std::size_t
    {
        if (Targets_.empty())
        {
            return RngNextU16(0, Cfg_.MaxPadBytes);
        }

        /// 选取当前 WriteCount 对应的 Target(循环使用)
        const auto &Target = Targets_[WriteCount_ % Targets_.size()];
        const auto TargetLen = RngNextU16(Target.MinVal, Target.MaxVal);

        if (DataLen < TargetLen)
        {
            return TargetLen - DataLen;
        }

        return RngNextU16(0, Cfg_.MaxPadBytes);
    }

    inline auto PadTransport::RngNextU16(std::uint16_t MinVal, std::uint16_t MaxVal) -> std::uint16_t
    {
        if (MinVal >= MaxVal)
        {
            return MinVal;
        }

        std::array<std::byte, 2> buf{};
        RngNextBytes(buf);

        const auto Raw =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(static_cast<std::uint8_t>(buf[0])) << 8) |
                                       static_cast<std::uint16_t>(static_cast<std::uint8_t>(buf[1])));

        // 用 uint32 计算区间，避免 MaxVal=65535 时 uint16 溢出为 0
        // 导致取模除零
        const auto Range = static_cast<std::uint32_t>(MaxVal) - MinVal + 1;
        return static_cast<std::uint16_t>(MinVal + (Raw % Range));
    }

    inline void PadTransport::RngRefill()
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, RngKey_.data());

        std::array<std::uint8_t, 8> CounterBytes{};
        auto Ctr = RngCounter_;
        for (std::size_t I = 0; I < 8; ++I)
        {
            CounterBytes[I] = static_cast<std::uint8_t>(Ctr & 0xFF);
            Ctr >>= 8;
        }
        blake3_hasher_update(&hasher, CounterBytes.data(), 8);
        blake3_hasher_finalize(&hasher, RngCache_.data(), 32);

        RngCachePos_ = 0;
        ++RngCounter_;
    }

    inline void PadTransport::RngNextBytes(std::span<std::byte> out)
    {
        std::size_t Offset = 0;
        while (Offset < out.size())
        {
            if (RngCachePos_ >= 32)
            {
                RngRefill();
            }

            std::size_t Chunk = 0;
            if (out.size() - Offset < 32 - RngCachePos_)
            {
                Chunk = out.size() - Offset;
            }
            else
            {
                Chunk = 32 - RngCachePos_;
            }
            std::memcpy(out.data() + Offset, RngCache_.data() + RngCachePos_, Chunk);
            RngCachePos_ += Chunk;
            Offset += Chunk;
        }
    }

    inline auto PadTransport::ParseTargets(std::string_view spec, Preview::Memory::ResourcePointer mr)
        -> Preview::Memory::Vector<PadTarget>
    {
        Preview::Memory::Vector<PadTarget> targets(mr);

        std::size_t Start = 0;
        while (Start <= spec.size())
        {
            auto end = spec.find(',', Start);
            if (end == std::string_view::npos)
            {
                end = spec.size();
            }

            const auto Token = spec.substr(Start, end - Start);
            if (!Token.empty())
            {
                PadTarget t{};

                auto Dash = Token.find('-');
                if (Dash != std::string_view::npos)
                {
                    auto MinStr = Token.substr(0, Dash);
                    auto MaxStr = Token.substr(Dash + 1);
                    std::uint16_t Mn = 0;
                    std::uint16_t Mx = 0;
                    std::from_chars(MinStr.data(), MinStr.data() + MinStr.size(), Mn);
                    std::from_chars(MaxStr.data(), MaxStr.data() + MaxStr.size(), Mx);
                    t.MinVal = Mn;
                    t.MaxVal = Mx;
                }
                else
                {
                    std::uint16_t Val = 0;
                    std::from_chars(Token.data(), Token.data() + Token.size(), Val);
                    t.MinVal = Val;
                    t.MaxVal = Val;
                }

                targets.push_back(t);
            }

            Start = end + 1;
        }

        return targets;
    }


} // namespace Preview::Transport
