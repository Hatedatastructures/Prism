#include <prism/config/validator.hpp>

#include <prism/foundation/exception/security.hpp>
#include <prism/foundation/fault/code.hpp>

#include <boost/asio.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>

namespace psm::config_validator
{
    namespace net = boost::asio;

    namespace
    {
        auto is_ip_literal(std::string_view host) noexcept -> bool
        {
            boost::system::error_code ec;
            net::ip::make_address(host, ec);
            return !ec;
        }

        auto is_file_readable(std::string_view path) noexcept -> bool
        {
            if (path.empty())
            {
                return false;
            }
            std::error_code ec;
            if (!std::filesystem::exists(path, ec))
            {
                return false;
            }
            std::ifstream f(std::string{path});
            return f.good();
        }

        auto append_error(memory::vector<memory::string> &errors, std::string_view msg) -> void
        {
            memory::string s(errors.get_allocator());
            s.append(msg.data(), msg.size());
            errors.push_back(std::move(s));
        }
    } // namespace

    auto validate(const psm::config &cfg) -> validation_result
    {
        validation_result result{};

        if (cfg.buffer.size == 0)
        {
            result.valid = false;
            append_error(result.errors, "buffer.size must be greater than 0");
        }

        if (cfg.instance.addressable.port == 0)
        {
            result.valid = false;
            append_error(result.errors, "instance.addressable.port must be greater than 0");
        }

        if (cfg.dns.cache_enabled && cfg.dns.servers.empty())
        {
            result.valid = false;
            append_error(result.errors, "dns.servers must not be empty when cache is enabled");
        }

        const auto check_proto = [&](std::string_view name, bool enabled)
        {
            if (!enabled)
            {
                result.valid = false;
                memory::string msg(result.errors.get_allocator());
                msg.append(name.data(), name.size());
                msg += ": at least one of enable_tcp/enable_udp must be true";
                result.errors.push_back(std::move(msg));
            }
        };
        check_proto("protocol.socks5", cfg.protocol.socks5.enable_tcp || cfg.protocol.socks5.enable_udp);
        check_proto("protocol.trojan", cfg.protocol.trojan.enable_tcp || cfg.protocol.trojan.enable_udp);
        check_proto("protocol.vless", cfg.protocol.vless.enable_udp);
        check_proto("protocol.shadowsocks", cfg.protocol.shadowsocks.enable_tcp || cfg.protocol.shadowsocks.enable_udp);

        for (const auto &[host, endpoint_config] : cfg.instance.reverse_map)
        {
            if (!is_ip_literal(endpoint_config.host))
            {
                result.valid = false;
                memory::string msg(result.errors.get_allocator());
                msg += "reverse_map[";
                msg += host;
                msg += "].host must be IP literal (got: ";
                msg += endpoint_config.host;
                msg += ")";
                result.errors.push_back(std::move(msg));
            }
            if (endpoint_config.port == 0)
            {
                result.valid = false;
                memory::string msg(result.errors.get_allocator());
                msg += "reverse_map[";
                msg += host;
                msg += "].port must be greater than 0";
                result.errors.push_back(std::move(msg));
            }
        }

        if (!cfg.instance.cert.cert.empty())
        {
            if (!is_file_readable(cfg.instance.cert.cert))
            {
                result.valid = false;
                memory::string msg(result.errors.get_allocator());
                msg += "instance.cert.cert file not readable: ";
                msg += cfg.instance.cert.cert;
                result.errors.push_back(std::move(msg));
            }
        }
        if (!cfg.instance.cert.key.empty())
        {
            if (!is_file_readable(cfg.instance.cert.key))
            {
                result.valid = false;
                memory::string msg(result.errors.get_allocator());
                msg += "instance.cert.key file not readable: ";
                msg += cfg.instance.cert.key;
                result.errors.push_back(std::move(msg));
            }
        }

        return result;
    }

    auto validate_or_throw(const psm::config &cfg) -> void
    {
        const auto result = validate(cfg);
        if (result.valid)
        {
            return;
        }
        memory::string combined("configuration validation failed:", result.errors.get_allocator());
        for (const auto &err : result.errors)
        {
            combined += "\n  - ";
            combined += err;
        }
        throw psm::exception::security(std::string{combined});
    }

} // namespace psm::config_validator
