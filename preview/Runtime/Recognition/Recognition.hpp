/**
 * @file Recognition.hpp
 * @brief 协议识别流水线
 * @details 首包探测 → TLS ClientHello/SNI（必要时）→ 方案包装 → 预读回注。
 *          输出 detected（协议类型）、scheme 和可继续读取的 transport。
 * @note TLS 解析与 SNI 路由为 Preview 自有实现；未配置路由表时 TLS 保持显式透传，
 *       配置路由表但未命中或方案未注册时默认拒绝。
 */

#pragma once

#include <string_view>
#include <vector>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Runtime/Recognition/Probe.hpp>
#include <preview/Runtime/Recognition/Protocol.hpp>
#include <preview/Runtime/Recognition/Route.hpp>
#include <preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <preview/Runtime/Recognition/Tls.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Snapshot.hpp>

namespace Preview::Recognition
{

    namespace net = boost::asio;

    /**
     * @struct RecognizeResult
     * @brief 识别结果
     */
    struct RecognizeResult
    {
        ProtocolType detected{ProtocolType::Unknown}; ///< 检测到的协议
        SharedTransmission transport;                  ///< 回注预读后的传输
        std::vector<std::byte> preread;              ///< 预读数据（供 handler 消费）
        std::string scheme;                          ///< 命中的伪装方案（TLS 时；当前恒空）
        bool success{false};                            ///< 识别成功
    };

    /**
     * @class Pipeline
     * @brief 识别流水线（Probe → TLS/SNI → scheme → 预读回注）
     * @details routes 与 executor 由启动层拥有并在会话生命周期内保持有效。
     *          scheme 执行前会回滚 Snapshot，保证包装器从 ClientHello 起点读取。
     */
    class Pipeline
    {
    public:
        /**
         * @brief 构造
         * @param Routes SNI 路由表（可选）
         * @param Executor 伪装方案执行器（可选）
         */
        explicit Pipeline(SniRouteTable *Routes = nullptr, SchemeExecutor *Executor = nullptr)
            : Routes_(Routes), Executor_(Executor)
        {
        }

        /**
         * @brief 执行识别
         * @param transport 入站传输（预读被消费，结果含回注）
         * @return 识别结果
         */
        [[nodiscard]] auto Recognize(SharedTransmission transport) -> net::awaitable<RecognizeResult>
        {
            RecognizeResult Result;
            if (!transport)
            {
                co_return Result;
            }

            auto ProbeRes = co_await Probe(*transport);
            // 预读数据保留（unknown 也回注，保持数据完整）
            Result.preread.assign(ProbeBytes(ProbeRes).begin(), ProbeBytes(ProbeRes).end());
            auto PrereadTransport = WrapPreread(std::move(transport), Result.preread);
            if (!ProbeRes.success)
            {
                // 未识别：透传原始传输（预读已回注）
                Result.transport = std::move(PrereadTransport);
                Result.success = false;
                co_return Result;
            }

            Result.detected = ProbeRes.Type;
            Result.success = true;

            if (ProbeRes.Type != ProtocolType::Tls)
            {
                Result.transport = std::move(PrereadTransport);
                co_return Result;
            }

            auto Snapshot = std::make_shared<Preview::Transport::Snapshot>(std::move(PrereadTransport));
            const auto [ReadError, Record] = co_await ReadTlsRecord(*Snapshot);
            if (ReadError != Error::None)
            {
                Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = false;
                co_return Result;
            }
            const auto [ParseError, Features] = ParseClientHello(Record);
            if (ParseError != Error::None)
            {
                Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = false;
                co_return Result;
            }

            // 未配置 SNI 表时，TLS 作为显式 native 透传保留。
            if (!Routes_)
            {
                Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                co_return Result;
            }

            const auto *Route = Routes_->LookupEntry(Features.ServerName);
            if (!Route)
            {
                Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = false;
                co_return Result;
            }
            Result.scheme = Route->Scheme;
            if (Route->Protocol != ProtocolType::Unknown)
            {
                Result.detected = Route->Protocol;
            }
            if (Result.scheme.empty())
            {
                if (Route->AllowFallback)
                {
                    Snapshot->Rewind();
                    Result.transport = std::move(Snapshot);
                    co_return Result;
                }
                Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = false;
                co_return Result;
            }
            if (!Executor_ || !Executor_->Has(Result.scheme))
            {
                Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = false;
                co_return Result;
            }
            Snapshot->Rewind();
            // 保留 Pipeline 自己的 shared_ptr；执行器可能消费传入所有权，失败时仍需回滚并回交。
            auto Wrapped = co_await Executor_->Execute(Result.scheme, Snapshot);
            if (!Wrapped)
            {
                // scheme 失败时保留同一字节起点，交由上层执行显式关闭或回退。
                Result.success = false;
                Result.transport = std::move(Snapshot);
                co_return Result;
            }
            Result.transport = std::move(Wrapped);
            co_return Result;
        }

    private:
        /**
         * @brief 探测结果的预读字节
         * @param res 探测结果
         * @return 预读字节 span
         */
        [[nodiscard]] static auto ProbeBytes(const ProbeResult &res) -> std::span<const std::byte>
        {
            return std::span<const std::byte>(res.PreRead.data(), res.PreReadSize);
        }

        /// SNI 路由表（预留，见类注释）
        SniRouteTable *Routes_;
        /// 伪装方案执行器（由启动层拥有）
        SchemeExecutor *Executor_;
    };

} // namespace Preview::Recognition
