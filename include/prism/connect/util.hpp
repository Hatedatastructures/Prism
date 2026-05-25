/**
 * @file util.hpp
 * @brief 连接工具函数
 * @details 通用工具函数，包括传输层解包、关闭和 mux 目标检测。
 */
#pragma once

#include <cstddef>
#include <cstdint>
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
     * @brief 多路复用开关
     * @details 控制多路复用功能是否启用。
     */
    enum class mux_switch : std::uint8_t
    {
        off,  ///< 禁用多路复用
        on    ///< 启用多路复用
    };

    /**
     * @brief 关闭裸指针指向的传输对象
     * @param trans 传输对象的裸指针，可为空
     * @details 安全地关闭传输连接，先尝试半关闭写方向再关闭。
     * 若指针为空则不做任何操作。
     */
    inline void shut_close(transport::transmission *trans) noexcept
    {
        if (trans)
        {
            if (auto *rel = trans->lowest_layer<transport::reliable>())
            {
                rel->shutdown_write();
            }
            trans->close();
        }
    }

    /**
     * @brief 关闭并释放智能指针持有的传输对象
     * @param trans 持有传输对象的智能指针
     * @details 先尝试半关闭写方向再关闭传输连接，然后释放智能指针持有的所有权。
     */
    inline void shut_close(shared_transmission &trans) noexcept
    {
        if (trans)
        {
            if (auto *rel = trans->lowest_layer<transport::reliable>())
            {
                rel->shutdown_write();
            }
            trans->close();
            trans.reset();
        }
    }

    /**
     * @brief 穿透 snapshot/preview 装饰层，提取底层原始传输的 shared_ptr
     * @details 用于 native TLS 等需要解包到 raw socket 的场景。
     * @param trans 传输层智能指针（可能被 snapshot/preview 包装）
     * @return 解包后的 shared_ptr，穿透所有装饰层
     */
    [[nodiscard]] inline auto peel_to_raw(shared_transmission trans)
        -> shared_transmission
    {
        while (trans)
        {
            if (auto *p = dynamic_cast<transport::preview *>(trans.get()))
            {
                trans = p->inner();
                continue;
            }
            if (auto *s = dynamic_cast<transport::snapshot *>(trans.get()))
            {
                trans = s->inner();
                continue;
            }
            break;
        }
        return trans;
    }

    /**
     * @brief 将 shared_transmission 动态转型为目标类型指针
     * @tparam T 目标类型（如 transport::snapshot）
     * @param t 传输层智能指针引用
     * @return T* 目标类型指针，转型失败返回 nullptr
     */
    template <typename T>
    [[nodiscard]] T *as(shared_transmission &t)
    {
        return dynamic_cast<T *>(t.get());
    }

    /**
     * @brief 检测是否为 mux 多路复用标记地址
     * @param host 目标主机名
     * @param mux 多路复用开关
     * @return 若目标地址为 mux 标记地址且 mux 已启用则返回 true
     * @details 检测目标主机名是否以 ".mux.sing-box.arpa" 结尾。
     */
    [[nodiscard]] inline auto is_mux_target(std::string_view host, mux_switch mux) noexcept
        -> bool
    {
        if (mux != mux_switch::on)
            return false;
        constexpr std::string_view suffix = ".mux.sing-box.arpa";
        return host.size() >= suffix.size() && host.substr(host.size() - suffix.size()) == suffix;
    }

} // namespace psm::connect
