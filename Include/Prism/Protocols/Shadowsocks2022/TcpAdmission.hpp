/** @file TcpAdmission.hpp @brief SS2022 多账户 wire 认证；候选检查不取得 quota/rate lease。 */
#pragma once
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Prepared.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <span>

namespace Prism::Shadowsocks2022
{
    /**
     * @brief 同步借用 Prepared 与 wire 字节做候选检查，不取 quota/rate lease。
     * @param Value 只借用到同步返回；不得在调用完成前销毁或修改 prepared credential。
     * @param Bytes 只借用到同步返回；span 的底层存储由调用者保持有效。
     * @return None 表示某个 key 完整且时间窗有效，NeedMore 表示仍需更多字节，BadAuth
     *         表示候选均失败；没有认证器、网络 executor、取消点或 stream half-close。
     */
    [[nodiscard]] auto InspectTcp(const Prepared& Value, std::span<const std::byte> Bytes)
        -> Prism::Error;
    /**
     * @brief TCP admission 的输入 owner：Inbound 由本值对象接管，Mux 只是共享 cold view。
     * @details AcceptTcp 会移动 Inbound 到 ReplayTransmission；Mux 不复制 prepared 或 lease，
     *          由 root factory 在 winner 成功后创建正式 mux root。
     */
    struct TcpIngress final
    {
        Prism::SharedTransmission Inbound;
        std::shared_ptr<Prism::Mux::RootBinding> Mux;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        Prism::Contract::InboundAdmission Admission;
    };
    /**
     * @brief 在入站 executor 上依次试验 prepared 凭据并发布唯一结果。
     * @param Input 按值接管 Inbound/Mux；调用方在协程返回前保持其 admission 及底层 executor 有效。
     * @param Value 借用整个 co_await 期间；调用者必须保持 Prepared 的 pin/material 有效。
     * @return winner 成功时只移动一次 account lease 并返回 stream/mux plane；仅 BadAuth 会回退
     *         试下个 PSK，全部失败返回 AuthFailed。I/O/wire 终止错误原样保留 Native。
     * @details 每个失败候选 Rewind 保留回放窗口，winner Commit 后才把写侧和真实
     *          connection 交给 stream 或 mux root。plain stream 支持半关闭，mux root 由 engine
     *          管理子流；取消依赖载体关闭与 Asio，不宣称每个错误有专用 cancel token。
     *          调用者 executor 负责驱动 I/O，异常不在此处转换为成功结果。
     */
    [[nodiscard]] auto AcceptTcp(TcpIngress Input, const Prepared& Value)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>;
} // namespace Prism::Shadowsocks2022
