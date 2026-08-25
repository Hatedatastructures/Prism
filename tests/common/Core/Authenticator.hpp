/**
 * @file Authenticator.hpp
 * @brief 协议认证器抽象（可注入）
 * @details 协议握手的凭据校验通过 Authenticator 接口完成：
 * - socks5：Check(用户名, 密码)（RFC 1929）
 * - trojan/vless：Check("", 凭据)（单凭据，身份为空）
 * - 生产实现接入账户目录（src/prism/user/Directory），
 *   测试用 StaticAuthenticator / RejectAuthenticator
 * @note 生命周期：Authenticator 由调用方持有（非拥有指针传入
 *       ServerConfig），协议 Conn 只调用不持有。
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>

namespace Preview
{

    /**
     * @brief 认证结果
     * @details Ok 表示凭据通过；identity 为通过后的用户标识
     * （供统计/审计按账户聚合）。
     */
    struct AuthResult
    {
        bool Ok{false};          ///< 认证是否通过
        std::string identity{};  ///< 用户标识（通过后有效）
    };

    /**
     * @class Authenticator
     * @brief 认证器抽象接口
     * @details 协议握手调用 Check() 校验凭据。实现：
     * - StaticAuthenticator：静态比对（测试默认）
     * - RejectAuthenticator：总是拒绝
     * - 生产账户目录认证器（src/prism/user/）
     */
    class Authenticator
    {
    public:
        virtual ~Authenticator() = default;

        /**
         * @brief 校验凭据
         * @param identity 身份标识（socks5 用户名；trojan/vless 传空）
         * @param Secret 凭据（socks5 密码；trojan/vless 为协议凭据）
         * @return 认证结果（通过时 identity 为用户标识）
         */
        [[nodiscard]] virtual auto Check(std::string_view identity, std::string_view Secret) const
            -> AuthResult = 0;
    };

    /**
     * @class StaticAuthenticator
     * @brief 静态比对认证器（测试默认）
     * @details 比对身份与凭据是否与配置一致，与旧协议行为等价
     * （ServerConfig 静态 username/password 校验）。
     */
    class StaticAuthenticator final : public Authenticator
    {
    public:
        /**
         * @brief 构造
         * @param identity 期望身份（socks5 用户名；单凭据协议传空）
         * @param Secret 期望凭据
         */
        explicit StaticAuthenticator(std::string identity, std::string Secret)
            : identity_(std::move(identity)), secret_(std::move(Secret))
        {
        }

        [[nodiscard]] auto Check(std::string_view identity, std::string_view Secret) const
            -> AuthResult override
        {
            if (identity != identity_ || Secret != secret_)
            {
                return {false, {}};
            }
            return {true, std::string(identity)};
        }

    private:
        std::string identity_; ///< 期望身份
        std::string secret_;   ///< 期望凭据
    };

    /**
     * @class RejectAuthenticator
     * @brief 总是拒绝的认证器（测试错误路径）
     */
    class RejectAuthenticator final : public Authenticator
    {
    public:
        [[nodiscard]] auto Check(std::string_view, std::string_view) const -> AuthResult override
        {
            return {false, {}};
        }
    };

    /**
     * @brief 便捷别名：认证器共享指针（持有者负责生命周期）
     */
    using SharedAuthenticator = std::shared_ptr<Authenticator>;

} // namespace Preview
