#include <prism/resource/session.hpp>
#include <prism/stealth/facade/reality/handshake.hpp>

#include <prism/config/config.hpp>
#include <prism/net/connect/outbound/dial.hpp>
#include <prism/net/connect/outbound/proxy.hpp>
#include <prism/net/net.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/stealth/recognition/tls/signal.hpp>
#include <prism/stealth/facade/reality/config.hpp>
#include <prism/stealth/facade/reality/seal.hpp>
#include <prism/stealth/facade/reality/util/auth.hpp>
#include <prism/stealth/facade/reality/util/keygen.hpp>
#include <prism/stealth/facade/reality/util/response.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <charconv>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>

using namespace psm::trace;

namespace psm::stealth::reality
{

    namespace tls = psm::protocol::tls;

    namespace
    {

        // 根据握手 transcript 重新计算并加密服务端 Finished 消息
        // TLS 1.3 的 Finished 包含 verify_data = HMAC(handshake_key, transcript_hash)
        // 此函数把正确计算的 Finished 替换到加密握手记录中
        auto derive_and_encrypt_finished(const key_material &keys, shello_result &sh_result, std::span<const std::uint8_t> chello_raw, std::shared_ptr<trace::trace_context> trace)
            -> fault::code
        {
            constexpr std::size_t FINISHED_MSG_SIZE = 36; // 类型(1) + 长度(3) + verify_data(32)
            const auto &old_plaintext = sh_result.enc_hs_plain;

            if (old_plaintext.size() < FINISHED_MSG_SIZE)
            {
                trace::warn<flt::conn | flt::protocol>(trace, "plaintext too short for Finished: {}", old_plaintext.size());
                return fault::code::kdferr;
            }

            // 握手 transcript = ClientHello || ServerHello || (EncryptedExtensions + Certificate + CertificateVerify)
            // Finished 只对前三个握手消息的 hash 做 HMAC，不包含自身
            const auto ee_cert_cv = std::span<const std::uint8_t>(
                old_plaintext.data(), old_plaintext.size() - FINISHED_MSG_SIZE);

            const auto transcript_for_finished = crypto::sha256(
                chello_raw,
                sh_result.shello_msg,
                ee_cert_cv);

            const auto verify_data = compute_verify(
                keys.server_finkey, transcript_for_finished);

            trace::debug<flt::conn | flt::protocol>(trace, "server Finished transcript computed");
            trace::debug<flt::conn | flt::protocol>(trace, "server Finished verify_data computed");

            // 用正确的 verify_data 构造新的 Finished 明文
            memory::vector<std::uint8_t> correct_plaintext(ee_cert_cv.begin(), ee_cert_cv.end());
            correct_plaintext.push_back(tls::HS_FINISHED);
            correct_plaintext.push_back(0x00);
            correct_plaintext.push_back(0x00);
            correct_plaintext.push_back(static_cast<std::uint8_t>(verify_data.size()));
            correct_plaintext.insert(correct_plaintext.end(), verify_data.begin(), verify_data.end());

            // 用服务端握手密钥加密整个记录（EncryptedExtensions + Certificate + CertificateVerify + Finished）
            auto [enc_ec, encrypted_record] = encrypt_record(
                encrypt_params{
                    keys.server_hskey,
                    keys.server_hsiv,
                    0,
                    tls::CT_HANDSHAKE,
                    correct_plaintext});

            if (fault::failed(enc_ec))
            {
                trace::warn<flt::conn | flt::protocol>(trace, "failed to encrypt handshake record");
                return enc_ec;
            }

            sh_result.enc_hs_plain = std::move(correct_plaintext);
            sh_result.enc_hs_record = std::move(encrypted_record);
            return fault::code::success;
        }


        // 读取并验证客户端的 Finished 消息
        // 客户端收到 ServerHello 后会用自己的握手密钥加密发送 Finished
        // 服务端用 client_hskey 解密验证，确认握手完整性
        auto consume_client_finished(transport::transmission &inbound, const key_material &keys, std::shared_ptr<trace::trace_context> trace)
            -> net::awaitable<fault::code>
        {
            bool consumed = false;
            while (!consumed)
            {
                auto [read_ec, rec] = co_await ::psm::tls::record::read(inbound);
                if (fault::failed(read_ec))
                {
                    trace::warn<flt::conn | flt::protocol>(trace, "failed to read client record");
                    co_return fault::code::io_error;
                }

                const auto rec_ctype = rec.header().content_type;
                const auto rec_len = rec.header().length;

                trace::debug<flt::conn | flt::protocol>(trace, "client rec: type=0x{:02x} len={}",
                             static_cast<unsigned>(rec_ctype), rec_len);

                // TLS 1.3 中间件兼容性 CCS 记录，直接跳过
                if (rec_ctype == tls::CT_CHANGE_CIPHER_SPEC)
                {
                    trace::debug<flt::conn | flt::protocol>(trace, "skipping client CCS record");
                    continue;
                }

                // 用客户端握手密钥解密记录
                {
                    // nonce = client_hsiv（TLS 1.3 中序列号从 0 开始，XOR 到 IV）
                    std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_nonce{};
                    std::memcpy(client_nonce.data(), keys.client_hsiv.data(), tls::AEAD_NONCE_LEN);

                    // 构造 additional data（record header）
                    memory::vector<std::byte> ad_buf = rec.serialize();
                    ad_buf.resize(tls::RECORD_HDR_LEN);
                    const auto ad_span = std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(ad_buf.data()), ad_buf.size());
                    const auto ct_span = std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(rec.payload().data()), rec.payload().size());

                    crypto::aead_context client_aead(
                        crypto::aead_cipher::aes_128_gcm,
                        std::span<const std::uint8_t>(keys.client_hskey.data(), keys.client_hskey.size()));

                    const auto pt_size = crypto::aead_context::open_size(rec.payload().size());
                    memory::vector<std::uint8_t> decrypted(pt_size);
                    const auto nonce_span = std::span<const std::uint8_t>(client_nonce.data(), client_nonce.size());

                    const auto open_ec = client_aead.open(crypto::open_input{decrypted, ct_span, nonce_span, ad_span});

                    if (!fault::failed(open_ec) && decrypted.size() >= 2)
                    {
                        // TLS 1.3 记录的最后一个字节是内层 content_type
                        const auto inner_ctype = decrypted.back();
                        if (inner_ctype == tls::CT_ALERT && decrypted.size() >= 3)
                        {
                            // 客户端拒绝了我们发出去的 ServerHello/证书，握手失败
                            trace::error<flt::conn | flt::protocol>(trace, "client sent TLS ALERT: level={}, desc=0x{:02x} — server Finished was rejected",
                                         static_cast<unsigned>(decrypted[0]),
                                         static_cast<unsigned>(decrypted[1]));
                            co_return fault::code::hsfail;
                        }
                        else
                        {
                            trace::debug<flt::conn | flt::protocol>(trace, "consumed client Finished record ({} bytes, inner_type=0x{:02x})",
                                         rec_len, static_cast<unsigned>(inner_ctype));
                        }
                    }
                    else
                    {
                        // 解密失败：客户端可能用了错误的密钥（说明不是合法 Reality 客户端）
                        trace::warn<flt::conn | flt::protocol>(trace, "failed to decrypt client record (ec={}), raw {} bytes",
                                    static_cast<int>(open_ec), rec_len);
                        co_return fault::code::hsfail;
                    }
                }
                consumed = true;
            }

            co_return fault::code::success;
        }


        // ── 阶段 ① 返回值：认证结果 + ClientHello 特征 ──────────────────────

        struct auth_stage_result
        {
            bool done = false;                                  // true=认证通过，走 Reality 握手
            stealth::handshake_result result;                   // 认证失败时填充错误信息
            memory::vector<std::uint8_t> raw_record;            // 原始 ClientHello TLS 记录
            tls::hello_features ch_features;                    // ClientHello 解析结果
            memory::vector<std::uint8_t> decoded_privkey;        // base64 解码后的服务端静态私钥
            auth_result auth_res;                               // 认证产出：auth_key + 临时密钥对
        };


        struct auth_client_args
        {
            transport::shared_transmission inbound;
            const psm::config &cfg;
            psm::resource::session &session;
            net::steady_timer &deadline;
            std::shared_ptr<trace::trace_context> trace;
        };


        // 阶段 ①：读取 ClientHello，尝试 Reality 认证
        //   认证通过 → done=true，上层继续 negotiate_tls
        //   SNI 不匹配 → done=false，result.preread 填充原始记录，交给下一个伪装方案
        //   ClientHello 解析失败 → 调用 fallback_dest 转发给真实网站
        auto authenticate_client(auth_client_args args)
            -> net::awaitable<auth_stage_result>
        {
            auth_stage_result out;
            auto &inbound = *args.inbound;
            const auto &reality_cfg = args.cfg.stealth.reality;
            const auto trace = args.trace;

            // 读取一个完整的 TLS 记录（ClientHello）
            auto [read_ec, raw_record] = co_await recognition::tls::read_tls_record(inbound);
            if (fault::failed(read_ec))
            {   // 读取失败，可能连接异常或对方不是 TLS 客户端，无法继续握手,取消定时器并返回错误
                args.deadline.cancel();
                trace::warn<flt::conn | flt::protocol>(trace, "failed to read TLS record: {}", fault::describe(read_ec));
                out.result.error = read_ec;
                if (read_ec == fault::code::canceled)
                    out.result.error = fault::code::timeout;
                co_return out;
            }

            // 解析 ClientHello 提取 SNI、key_share、session_id 等特征
            auto [parse_ec, ch_features] = recognition::tls::parse_client_hello(raw_record);
            if (fault::failed(parse_ec))
            {   // 解析失败，取消定时器并返回错误
                args.deadline.cancel();
                trace::warn<flt::conn | flt::protocol>(trace, "failed to parse ClientHello: {}", fault::describe(parse_ec));
                // ClientHello 格式异常，连解析都做不到，直接转发给真实网站兜底
                const auto fb_ec = co_await fallback_dest(args.session, args.inbound, raw_record, args.trace);
                if (fault::succeeded(fb_ec))
                {
                    out.result.scheme = "reality";
                    out.result.error = fault::code::success;
                }
                else
                {
                    out.result.error = fb_ec;
                }
                co_return out;
            }

            trace::debug<flt::conn | flt::protocol>(trace, "ClientHello parsed, SNI: {}", ch_features.server_name);

            // base64 解码服务端静态 X25519 私钥（配置中的 private_key）
            const auto private_key_str = std::string(reality_cfg.private_key.data(), reality_cfg.private_key.size());
            auto decoded_key_str = crypto::base64_decode(private_key_str);
            if (decoded_key_str.size() != tls::REALITY_KEY_LEN)
            {
                args.deadline.cancel();
                trace::warn<flt::conn | flt::protocol>(trace, "invalid private key length: {}", decoded_key_str.size());
                // 私钥配置错误，无法做 Reality 认证，转发给真实网站
                const auto fb_ec = co_await fallback_dest(args.session, args.inbound, raw_record, args.trace);
                if (fault::succeeded(fb_ec))
                {
                    out.result.scheme = "reality";
                    out.result.error = fault::code::success;
                }
                else
                {
                    out.result.error = fb_ec;
                }
                co_return out;
            }

            out.raw_record = std::move(raw_record);
            out.ch_features = std::move(ch_features);
            // 安全：decoded_privkey 现在拥有数据所有权（memory::vector），类型转换安全
            out.decoded_privkey.assign(
                reinterpret_cast<const std::uint8_t *>(decoded_key_str.data()),
                reinterpret_cast<const std::uint8_t *>(decoded_key_str.data() + decoded_key_str.size()));

            // 核心认证：X25519 密钥交换 → 派生 auth_key → AES-GCM 解密 session_id → 验证 short_id
            auto [auth_ec, auth_res] = authenticate(reality_cfg, out.ch_features, out.decoded_privkey);
            if (!auth_res.authenticated)
            {
                args.deadline.cancel();
                // 安全：将 uint8_t 记录数据转为 byte 迭代器用于 preread 赋值，二进制兼容
                auto set_preread = [&](stealth::handshake_result &r)
                {
                    r.transport = args.inbound;
                    r.detected = psm::connect::protocol_type::tls;
                    r.preread.assign(
                        reinterpret_cast<const std::byte *>(out.raw_record.data()),
                        reinterpret_cast<const std::byte *>(out.raw_record.data() + out.raw_record.size()));
                };

                if (auth_ec == fault::code::badsni)
                {
                    // SNI 不在 server_names 白名单 → 不是 Reality 客户端，交给下一个伪装方案
                    trace::debug<flt::conn | flt::protocol>(trace, "SNI mismatch, falling back to standard TLS");
                    set_preread(out.result);
                    co_return out;
                }
                if (out.ch_features.server_name.empty())
                {
                    // 空 SNI → 无法匹配任何方案，交给下一个伪装方案
                    trace::debug<flt::conn | flt::protocol>(trace, "auth failed with empty SNI, falling back to standard TLS");
                    set_preread(out.result);
                    co_return out;
                }
                // short_id 错误或无 X25519 key_share → 不是 Reality 客户端
                trace::debug<flt::conn | flt::protocol>(trace, "auth failed: {}, not Reality, passing to next scheme", fault::describe(auth_ec));
                set_preread(out.result);
                co_return out;
            }

            trace::info<flt::conn | flt::protocol>(trace, "authentication successful");
            out.auth_res = std::move(auth_res);
            out.done = true;
            co_return out;
        }


        // ── 阶段 ② 返回值：TLS 1.3 密钥协商结果 ──────────────────────────

        struct negotiate_result
        {
            bool done = false;
            stealth::handshake_result result;
            key_material keys;                                  // 握手密钥 + 应用密钥（后续 derive_app_keys 填充）
            shello_result sh_result;                            // ServerHello 消息 + 加密记录
            memory::vector<std::uint8_t> shared_secret;         // 临时 X25519 共享密钥
        };


        // 阶段 ②：纯本地计算，完成 TLS 1.3 密钥协商
        // 生成 ServerHello、伪造证书、派生所有握手密钥，不涉及网络 I/O
        auto negotiate_tls(
            const tls::hello_features &ch_features,
            const auth_result &auth_res,
            net::steady_timer &deadline,
            std::shared_ptr<trace::trace_context> trace)
            -> negotiate_result
        {
            negotiate_result out;

            // 第二次 X25519：用服务端临时密钥对（authenticate 中生成的）与客户端公钥交换
            // 这次跟认证用的静态私钥不同，是临时的，提供前向安全性
            auto [ephemeral_ec, shared_secret] = crypto::x25519(
                std::span<const std::uint8_t>(auth_res.server_ephkey.private_key.data(),
                                              auth_res.server_ephkey.private_key.size()),
                std::span<const std::uint8_t>(ch_features.x25519_key.data(),
                                              ch_features.x25519_key.size()));
            if (fault::failed(ephemeral_ec))
            {
                deadline.cancel();
                trace::warn<flt::conn | flt::protocol>(trace, "ephemeral X25519 key exchange failed");
                out.result.error = ephemeral_ec;
                return out;
            }

            // 构造 ServerHello + 伪造 Ed25519 证书 + 加密握手记录
            // 证书签名 = HMAC-SHA512(auth_key, ed25519_pubkey)，客户端能通过 auth_key 自行验证
            key_material dummy_keys{};
            auto [sh_ec, sh_result] = generate_shello(
                hello_request{
                    ch_features,
                    auth_res.server_ephkey.public_key,
                    dummy_keys,
                    {},
                    ch_features.raw_msg,
                    std::span<const std::uint8_t>(auth_res.auth_key.data(), auth_res.auth_key.size())});

            if (fault::failed(sh_ec))
            {
                deadline.cancel();
                trace::warn<flt::conn | flt::protocol>(trace, "failed to generate ServerHello: {}", fault::describe(sh_ec));
                out.result.error = sh_ec;
                return out;
            }

            // TLS 1.3 密钥调度：shared_secret → handshake_secret → 双向握手密钥
            // 输出 server_hskey/client_hskey + server_hsiv/client_hsiv + master_secret
            auto [ks_ec, keys] = derive_hs_keys(
                shared_secret,
                ch_features.raw_msg,
                sh_result.shello_msg);

            if (fault::failed(ks_ec))
            {
                deadline.cancel();
                trace::warn<flt::conn | flt::protocol>(trace, "failed to derive keys: {}", fault::describe(ks_ec));
                out.result.error = ks_ec;
                return out;
            }

            // 根据完整 transcript 重新计算服务端 Finished 的 verify_data 并加密
            const auto finished_ec = derive_and_encrypt_finished(keys, sh_result, ch_features.raw_msg, trace);
            if (fault::failed(finished_ec))
            {
                deadline.cancel();
                out.result.error = finished_ec;
                return out;
            }

            out.keys = std::move(keys);
            out.sh_result = std::move(sh_result);
            out.shared_secret.assign(shared_secret.begin(), shared_secret.end());
            out.done = true;
            return out;
        }


        // ── 阶段 ③ 参数 ──────────────────────────────────────────────────

        struct complete_hello_args
        {
            transport::transmission &inbound;
            const key_material &keys;
            const shello_result &sh_result;
            net::steady_timer &deadline;
            std::shared_ptr<trace::trace_context> trace;
        };


        // 阶段 ③：把 ServerHello + 加密握手记录发给客户端，然后读取并验证客户端 Finished
        auto complete_hello(complete_hello_args args)
            -> net::awaitable<std::pair<fault::code, bool>>
        {
            const auto trace = args.trace;
            // 合并三条记录一次性发送，减少系统调用：
            //   [ServerHello 明文记录][CCS 兼容记录][加密握手记录（证书+Finished）]
            {
                std::error_code write_ec;
                const auto &sh_rec = args.sh_result.shello_record;
                const auto &ccs_rec = args.sh_result.ccs_record;
                const auto &ehs_rec = args.sh_result.enc_hs_record;
                const std::size_t hs_total = sh_rec.size() + ccs_rec.size() + ehs_rec.size();
                memory::vector<std::byte> hs_combined(hs_total);
                std::size_t hs_off = 0;
                std::memcpy(hs_combined.data() + hs_off, sh_rec.data(), sh_rec.size());
                hs_off += sh_rec.size();
                std::memcpy(hs_combined.data() + hs_off, ccs_rec.data(), ccs_rec.size());
                hs_off += ccs_rec.size();
                std::memcpy(hs_combined.data() + hs_off, ehs_rec.data(), ehs_rec.size());
                co_await transport::async_write(args.inbound, hs_combined, write_ec);
                if (write_ec)
                {
                    args.deadline.cancel();
                    trace::warn<flt::conn | flt::protocol>(trace, "failed to send handshake records: {}", write_ec.message());
                    auto err = fault::to_code(write_ec);
                    if (err == fault::code::canceled)
                        err = fault::code::timeout;
                    co_return std::pair{err, false};
                }
            }

            // 等待客户端发回 Finished，用 client_hskey 解密验证
            const auto consumed_ec = co_await consume_client_finished(args.inbound, args.keys, args.trace);
            if (fault::failed(consumed_ec))
            {
                args.deadline.cancel();
                co_return std::pair{consumed_ec, false};
            }

            co_return std::pair{fault::code::success, true};
        }
    } // namespace


    // 解析 "host:port" 格式的 dest 配置（如 "www.microsoft.com:443"）
    auto parse_dest(const std::string_view dest, std::string &host, std::uint16_t &port)
        -> bool
    {
        if (dest.empty())
            return false;

        const auto colon_pos = dest.rfind(':');
        if (colon_pos == std::string_view::npos)
        {
            host = dest;
            port = 443;
            return true;
        }

        // IPv6 地址格式：[::1]:443
        if (dest.find(']') != std::string_view::npos)
        {
            const auto bracket_end = dest.find(']');
            if (bracket_end == std::string_view::npos)
                return false;
            host = dest.substr(1, bracket_end - 1);
            if (bracket_end + 2 < dest.size() && dest[bracket_end + 1] == ':')
            {
                const auto port_sv = dest.substr(bracket_end + 2);
                std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
            }
            else
            {
                port = 443;
            }
            return true;
        }

        host = dest.substr(0, colon_pos);
        {
            const auto port_sv = dest.substr(colon_pos + 1);
            const auto [ptr, fc_ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
            if (fc_ec != std::errc())
                return false;
        }
        return true;
    }


    // 回退路径：连接 dest 配置的真实网站，将客户端的 ClientHello 原封不动转发过去
    // 之后双向透传，审查者探测时会看到与真实网站完全正常的 TLS 通信
    auto fallback_dest(psm::resource::session &session, transport::shared_transmission inbound, const std::span<const std::uint8_t> raw_record, std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<fault::code>
    {
        const auto &reality_cfg = session.worker->process->cfg->stealth.reality;

        std::string dest_host;
        std::uint16_t dest_port = 443;
        if (!parse_dest(std::string_view(reality_cfg.dest.data(), reality_cfg.dest.size()), dest_host, dest_port))
        {
            trace::error<flt::conn | flt::protocol>(trace, "invalid dest config: {}", reality_cfg.dest);
            co_return fault::code::unreach;
        }

        trace::info<flt::conn | flt::protocol>(trace, "falling back to {}:{}", dest_host, dest_port);

        // 通过 outbound::dial 统一入口建立 TCP 连接到真实网站
        auto reality_wr = session.worker;
        if (!reality_wr)
        {
            trace::warn<flt::conn | flt::protocol>(trace, "worker resources expired before reality fallback dial");
            co_return fault::code::unreach;
        }
        char dest_port_buf[8];
        const auto [dest_port_end, dest_port_ec] = std::to_chars(dest_port_buf, dest_port_buf + sizeof(dest_port_buf), dest_port);
        auto dest_port_str = std::string_view(dest_port_buf, std::distance(dest_port_buf, dest_port_end));
        psm::connect::target dest_target;
        dest_target.host = memory::string(dest_host, session.arena.get());
        dest_target.port = memory::string(dest_port_str, session.arena.get());
        dest_target.positive = true;
        psm::outbound::dial_options dial_opts;
        dial_opts.trace = trace;
        dial_opts.allow_reverse = false;
        auto dial_res = co_await psm::outbound::dial({*reality_wr->outbound, reality_wr->ioc, reality_wr->traffic}, dest_target, dial_opts);
        if (fault::failed(dial_res.code) || !dial_res.transport)
        {
            trace::warn<flt::conn | flt::protocol>(trace, "connect to dest failed: {}", fault::describe(dial_res.code));
            co_return fault::code::unreach;
        }
        auto dest_trans = std::move(dial_res.transport);

        // 把客户端发来的原始 ClientHello TLS 记录转发给真实网站
        // dest_trans 是 shared_transmission，通过 transport::async_write 自由函数写入
        auto write_record_span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(raw_record.data()), raw_record.size());
        std::error_code write_ec;
        co_await transport::async_write(*dest_trans, write_record_span, write_ec);
        if (write_ec)
        {
            trace::warn<flt::conn | flt::protocol>(trace, "write to dest failed: {}", write_ec.message());
            co_return fault::code::unreach;
        }

        // 双向透传：客户端 ←→ Prism ←→ 真实网站
        connect::tunnel_options t_opts;
        t_opts.inbound = inbound;
        t_opts.outbound = std::move(dest_trans);
        t_opts.buffer_size = session.buffer;
        t_opts.traffic = &reality_wr->traffic;
        t_opts.detected = session.detected;
        t_opts.lease = &session.lease;
        co_await connect::tunnel(std::move(t_opts));

        trace::debug<flt::conn | flt::protocol>(trace, "fallback tunnel completed");
        co_return fault::code::success;
    }


    // 连接到真实网站完成 TLS 握手，提取其 DER 格式证书
    // 用于 Reality 伪造证书时参考（目前未在主流程中直接使用，预留给未来改进）
    auto fetch_dest_cert(const std::string_view host, const std::uint16_t port, outbound::proxy &outbound, const net::any_io_executor &executor, std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        memory::vector<std::uint8_t> empty_cert;

        try
        {
            char cert_port_buf[8];
            const auto [cert_port_end, cert_port_ec2] = std::to_chars(cert_port_buf, cert_port_buf + sizeof(cert_port_buf), port);
            auto cert_port_str = std::string_view(cert_port_buf, std::distance(cert_port_buf, cert_port_end));

            // 通过 outbound 接口拨号
            psm::connect::target cert_target;
            cert_target.host = memory::string(host, memory::current_resource());
            cert_target.port = memory::string(cert_port_str, memory::current_resource());
            cert_target.positive = true;
            auto [connect_ec, dest_trans] = co_await outbound.async_connect(cert_target, executor);
            if (fault::failed(connect_ec) || !dest_trans)
            {
                trace::warn<flt::conn | flt::protocol>(trace, "connect to dest for cert failed: {}", fault::describe(connect_ec));
                co_return std::pair{fault::code::st_certfail, empty_cert};
            }

            // 从 reliable transport 释放裸 socket 用于 TLS 客户端握手
            auto *rel = dest_trans->template lowest_layer<transport::reliable>();
            if (!rel)
            {
                trace::warn<flt::conn | flt::protocol>(trace, "dest transport is not reliable");
                co_return std::pair{fault::code::st_certfail, empty_cert};
            }
            auto socket_opt = rel->release_socket();
            if (!socket_opt)
            {
                trace::warn<flt::conn | flt::protocol>(trace, "dest transport has no raw socket");
                co_return std::pair{fault::code::st_certfail, empty_cert};
            }

            // 以客户端身份与真实网站建立 TLS 连接
            namespace ssl_local = net::ssl;
            ssl_local::context ssl_ctx(ssl_local::context::tls_client);
            ssl_ctx.set_verify_mode(ssl_local::verify_none);

            ssl_local::stream<net::ip::tcp::socket> ssl_stream(std::move(*socket_opt), ssl_ctx);
            SSL_set_tlsext_host_name(ssl_stream.native_handle(), std::string(host).c_str());

            boost::system::error_code ec;
            co_await ssl_stream.async_handshake(ssl_local::stream_base::client,
                                                net::redirect_error(trace::use_prefix_awaitable, ec));
            if (ec)
            {
                trace::warn<flt::conn | flt::protocol>(trace, "TLS handshake to dest failed: {}", ec.message());
                co_return std::pair{fault::code::st_certfail, empty_cert};
            }

            // 提取对端证书，转为 DER 格式
            auto *ssl_native = ssl_stream.native_handle();
            memory::vector<std::uint8_t> cert_der;

            auto *peer_cert = SSL_get_peer_certificate(ssl_native);
            if (peer_cert)
            {
                auto *bio = BIO_new(BIO_s_mem());
                i2d_X509_bio(bio, peer_cert);
                char *data = nullptr;
                const auto len = BIO_get_mem_data(bio, &data);
                // 安全：BIO 返回 char* 指向内部内存，转为 uint8_t 用于提取 DER 证书
                cert_der.insert(cert_der.end(),
                                reinterpret_cast<std::uint8_t *>(data),
                                reinterpret_cast<std::uint8_t *>(data + len));
                BIO_free(bio);
                X509_free(peer_cert);
            }

            boost::system::error_code shutdown_ec;
            ssl_stream.shutdown(shutdown_ec);

            if (cert_der.empty())
            {
                trace::warn<flt::conn | flt::protocol>(trace, "failed to extract certificate from dest");
                co_return std::pair{fault::code::st_certfail, empty_cert};
            }

            trace::debug<flt::conn | flt::protocol>(trace, "fetched dest certificate ({} bytes)", cert_der.size());
            co_return std::pair{fault::code::success, std::move(cert_der)};
        }
        catch (const std::exception &e)
        {
            trace::warn<flt::conn | flt::protocol>(trace, "exception fetching cert: {}", e.what());
            co_return std::pair{fault::code::st_certfail, empty_cert};
        }
    }


    // ══════════════════════════════════════════════════════════════════════
    // 主入口：Reality 握手四阶段流水线
    //
    // 1. authenticate_client  → 读取 ClientHello，认证 session_id
    //     认证失败 → fallback_dest（转发给真实网站）或交给下一个伪装方案
    //     认证成功 → 继续
    // 2. negotiate_tls        → 本地完成 TLS 1.3 密钥协商（无网络 I/O）
    // 3. complete_hello        → 发送 ServerHello + 接收客户端 Finished
    // 4. 建立 seal 传输层      → 派生应用密钥，读取内层协议数据
    // ══════════════════════════════════════════════════════════════════════
    auto handshake(transport::shared_transmission inbound, const psm::config &cfg, psm::resource::session &session, std::shared_ptr<trace::trace_context> trace)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!inbound)
        {   // 传输层无效，无法继续握手
            trace::warn<flt::conn | flt::protocol>(trace, "invalid inbound transmission");
            result.error = fault::code::io_error;
            co_return result;
        }

        // 30 秒握手超时保护
        net::steady_timer deadline(inbound->executor(), std::chrono::seconds(30));
        auto on_deadline = [&inbound](const boost::system::error_code &ec)
        {
            if (!ec) inbound->cancel();
        };
        deadline.async_wait(std::move(on_deadline));

        // 阶段 1：读取 ClientHello，尝试 Reality 认证
        // authenticate 内部：X25519(静态私钥, 客户端公钥) → 派生 auth_key → AES-GCM 解密 session_id → 验证 short_id
        auto auth = co_await authenticate_client({inbound, cfg, session, deadline, trace});
        if (!auth.done)
        {
            co_return auth.result;
        }

        // 阶段 2：本地完成 TLS 1.3 密钥协商
        // X25519(临时私钥, 客户端公钥) → 构造 ServerHello + 伪造证书 → 派生握手密钥
        auto nego = negotiate_tls(auth.ch_features, auth.auth_res, deadline, trace);
        if (!nego.done)
        {
            co_return nego.result;
        }

        // 阶段 3：发送握手记录给客户端，等待客户端 Finished 验证
        auto [hello_ec, hello_ok] = co_await complete_hello({*inbound, nego.keys, nego.sh_result, deadline, trace});
        if (!hello_ok)
        {
            result.error = hello_ec;
            if (result.error == fault::code::canceled)
                result.error = fault::code::timeout;
            co_return result;
        }

        // 阶段 4：派生应用流量密钥，建立 seal 加密传输层

        // 完整握手 transcript = ClientHello || ServerHello || 加密握手明文
        const auto full_transcript_hash = crypto::sha256(
            std::span<const std::uint8_t>(auth.ch_features.raw_msg.data(), auth.ch_features.raw_msg.size()),
            std::span<const std::uint8_t>(nego.sh_result.shello_msg.data(), nego.sh_result.shello_msg.size()),
            std::span<const std::uint8_t>(nego.sh_result.enc_hs_plain.data(), nego.sh_result.enc_hs_plain.size()));

        // master_secret → server_appkey/client_appkey + IVs
        const auto app_ec = derive_app_keys(nego.keys.master_secret,
                                                    {full_transcript_hash.data(), full_transcript_hash.size()}, nego.keys);
        if (fault::failed(app_ec))
        {   // 派生应用密钥失败，无法建立加密隧道
            deadline.cancel();
            trace::warn<flt::conn | flt::protocol>(trace, "failed to derive application keys");
            result.error = app_ec;
            co_return result;
        }

        // seal 是自定义的 TLS ApplicationData 读写层：
        //   读：TLS 记录 → AES-128-GCM 解密 → 去零填充 → 返回明文
        //   写：明文 + 填充 → AES-128-GCM 加密 → 构造 TLS 记录 → 发送
        auto reality_session = std::make_shared<seal>(
            std::move(inbound), nego.keys);

        // 从加密隧道中读取 64 字节内层协议数据，Probe 识别协议类型
        constexpr std::size_t preread_size = 64;
        memory::vector<std::byte> inner_buf(preread_size);
        std::error_code read_inner_ec;
        const auto inner_n = co_await reality_session->async_read_some(
            std::span<std::byte>(inner_buf.data(), preread_size), read_inner_ec);

        if (read_inner_ec || inner_n == 0)
        {
            deadline.cancel();
            trace::warn<flt::conn | flt::protocol>(trace, "failed to read inner data: {}", read_inner_ec.message());
            result.error = fault::to_code(read_inner_ec);
            co_return result;
        }

        result.transport = std::move(reality_session);
        result.detected = psm::connect::protocol_type::unknown;
        result.preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));
        result.scheme = "reality";
        result.error = fault::code::success;

        deadline.cancel();
        trace::info<flt::conn | flt::protocol>(trace, "handshake completed successfully");
        co_return result;
    }
} // namespace psm::stealth::reality
