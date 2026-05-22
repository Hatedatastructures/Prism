/**
 * @file util.hpp
 * @brief 连接工具函数
 * @details 通用工具函数，包括传输层查找、关闭和 mux 目标检测。
 */
#pragma once

#include <cstddef>
#include <memory>
#include <string_view>

#include <prism/transport/transmission.hpp>
#include <prism/transport/preview.hpp>
#include <prism/transport/snapshot.hpp>
#include <prism/transport/reliable.hpp>

namespace psm::connect
{
    using shared_transmission = transport::shared_transmission;

    /**
     * @brief 关闭裸指针指向的传输对象
     * @param trans 传输对象的裸指针，可为空
     * @details 安全地关闭传输连接，若指针为空则不做任何操作。
     */
    inline void shut_close(transport::transmission *trans) noexcept
    {
        if (trans)
        {
            trans->shutdown_write();
            trans->close();
        }
    }

    /**
     * @brief 关闭并释放智能指针持有的传输对象
     * @param trans 持有传输对象的智能指针
     * @details 先关闭传输连接，然后释放智能指针持有的所有权。
     */
    inline void shut_close(shared_transmission &trans) noexcept
    {
        if (trans)
        {
            trans->shutdown_write();
            trans->close();
            trans.reset();
        }
    }

    /**
     * @brief 从传输层包装链中解包找到底层 reliable 传输
     * @details 穿透 snapshot/preview 等装饰层，找到底层的 TCP socket 传输。
     * 用于 ShadowTLS/Restls 等需要直接操作 raw socket 的 scheme。
     * @param trans 传输层智能指针（可能被 snapshot/preview 包装）
     * @return reliable 传输的裸指针，找不到返回 nullptr
     */
    inline auto find_reliable(shared_transmission &trans) noexcept
        -> transport::reliable *
    {
        auto *raw = trans.get();
        while (raw)
        {
            if (auto *p = dynamic_cast<transport::preview *>(raw))
            {
                raw = p->inner().get();
                continue;
            }
            if (auto *s = dynamic_cast<transport::snapshot *>(raw))
            {
                raw = s->inner().get();
                continue;
            }
            break;
        }
        return dynamic_cast<transport::reliable *>(raw);
    }

    /**
     * @brief 检测是否为 mux 多路复用标记地址
     * @param host 目标主机名
     * @param mux_enabled 是否启用多路复用
     * @return 若目标地址为 mux 标记地址且 mux 已启用则返回 true
     * @details 检测目标主机名是否以 ".mux.sing-box.arpa" 结尾。
     */
    [[nodiscard]] inline auto is_mux_target(std::string_view host, bool mux_enabled) noexcept -> bool
    {
        constexpr std::string_view suffix = ".mux.sing-box.arpa";
        return mux_enabled && host.size() >= suffix.size() && host.substr(host.size() - suffix.size()) == suffix;
    }

} // namespace psm::connect
