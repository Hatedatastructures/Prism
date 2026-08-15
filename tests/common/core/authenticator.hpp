/**
 * @file authenticator.hpp
 * @brief 协议认证器抽象（可注入）
 * @details 协议握手的凭据校验通过 authenticator 接口完成：
 * - socks5：check(用户名, 密码)（RFC 1929）
 * - trojan/vless：check("", 凭据)（单凭据，身份为空）
 * - 生产实现接入账户目录（src/prism/user/directory），
 *   测试用 static_authenticator / reject_authenticator
 * @note 生命周期：authenticator 由调用方持有（非拥有指针传入
 *       server_config），协议 conn 只调用不持有。
 */

#pragma once

#include <string>
#include <string_view>

namespace psmtest
{

    /**
     * @brief 认证结果
     * @details ok 表示凭据通过；identity 为通过后的用户标识
     * （供统计/审计按账户聚合）。
     */
    struct auth_result
    {
        bool ok{false};          ///< 认证是否通过
        std::string identity{};  ///< 用户标识（通过后有效）
    };

    /**
     * @class authenticator
     * @brief 认证器抽象接口
     * @details 协议握手调用 check() 校验凭据。实现：
     * - static_authenticator：静态比对（测试默认）
     * - reject_authenticator：总是拒绝
     * - 生产账户目录认证器（src/prism/user/）
     */
    class authenticator
    {
    public:
        virtual ~authenticator() = default;

        /**
         * @brief 校验凭据
         * @param identity 身份标识（socks5 用户名；trojan/vless 传空）
         * @param secret 凭据（socks5 密码；trojan/vless 为协议凭据）
         * @return 认证结果（通过时 identity 为用户标识）
         */
        [[nodiscard]] virtual auto check(std::string_view identity, std::string_view secret) const
            -> auth_result = 0;
    };

    /**
     * @class static_authenticator
     * @brief 静态比对认证器（测试默认）
     * @details 比对身份与凭据是否与配置一致，与旧协议行为等价
     * （server_config 静态 username/password 校验）。
     */
    class static_authenticator final : public authenticator
    {
    public:
        /**
         * @brief 构造
         * @param identity 期望身份（socks5 用户名；单凭据协议传空）
         * @param secret 期望凭据
         */
        explicit static_authenticator(std::string identity, std::string secret)
            : identity_(std::move(identity)), secret_(std::move(secret))
        {
        }

        [[nodiscard]] auto check(std::string_view identity, std::string_view secret) const
            -> auth_result override
        {
            if (identity != identity_ || secret != secret_)
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
     * @class reject_authenticator
     * @brief 总是拒绝的认证器（测试错误路径）
     */
    class reject_authenticator final : public authenticator
    {
    public:
        [[nodiscard]] auto check(std::string_view, std::string_view) const -> auth_result override
        {
            return {false, {}};
        }
    };

    /**
     * @brief 便捷别名：认证器共享指针（持有者负责生命周期）
     */
    using shared_authenticator = std::shared_ptr<authenticator>;

} // namespace psmtest
