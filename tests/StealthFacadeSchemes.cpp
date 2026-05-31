/**
 * @file StealthFacadeSchemes.cpp
 * @brief Reality/Restls/ShadowTLS 方案纯接口测试
 */

#include <prism/config.hpp>
#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>
#include <prism/stealth/facade/restls/scheme.hpp>
#include <prism/stealth/facade/shadowtls/scheme.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/trace/spdlog.hpp>

#include <string_view>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    // ─── Reality ──────────────────────────────────────

    void TestRealityName(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        runner.Check(s.name() == "reality", "reality: name");
    }

    void TestRealityTier(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        runner.Check(s.tier() == 0, "reality: tier=0");
    }

    void TestRealityUnique(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        runner.Check(s.unique(), "reality: unique=true");
    }

    void TestRealityCategory(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        runner.Check(s.category() == psm::stealth::scheme_category::facade,
                     "reality: category=facade");
    }

    void TestRealityActiveDisabled(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        runner.Check(!s.active(cfg), "reality: active disabled by default");
    }

    void TestRealityActivePartial(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        cfg.stealth.reality.dest = psm::memory::string("example.com:443");
        runner.Check(!s.active(cfg), "reality: active disabled without key+snis");
    }

    void TestRealityActiveEnabled(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        cfg.stealth.reality.dest = psm::memory::string("example.com:443");
        cfg.stealth.reality.private_key = psm::memory::string("base64key==");
        cfg.stealth.reality.server_names.push_back(psm::memory::string("sni.example.com"));
        runner.Check(s.active(cfg), "reality: active enabled with all fields");
    }

    void TestRealitySnis(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        cfg.stealth.reality.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.reality.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        runner.Check(snis.size() == 2, "reality: snis count=2");
        runner.Check(snis[0] == "a.example.com", "reality: snis[0]");
        runner.Check(snis[1] == "b.example.com", "reality: snis[1]");
    }

    void TestRealitySnisEmpty(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        runner.Check(snis.empty(), "reality: snis empty by default");
    }

    void TestRealityGuess(TestRunner &runner)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        runner.Check(result.score == 450, "reality: guess score=450");
        runner.Check(result.solo_flag == 0, "reality: guess solo_flag=0");
    }

    // ─── Restls ──────────────────────────────────────

    void TestRestlsName(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        runner.Check(s.name() == "restls", "restls: name");
    }

    void TestRestlsTier(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        runner.Check(s.tier() == 2, "restls: tier=2");
    }

    void TestRestlsUnique(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        runner.Check(!s.unique(), "restls: unique=false");
    }

    void TestRestlsCategory(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        runner.Check(s.category() == psm::stealth::scheme_category::facade,
                     "restls: category=facade");
    }

    void TestRestlsActiveDisabled(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        runner.Check(!s.active(cfg), "restls: active disabled by default");
    }

    void TestRestlsActivePartial(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("sni.example.com"));
        runner.Check(!s.active(cfg), "restls: active disabled without host+password");
    }

    void TestRestlsActiveEnabled(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("sni.example.com"));
        cfg.stealth.restls.host = psm::memory::string("backend:443");
        cfg.stealth.restls.password = psm::memory::string("secretpass");
        runner.Check(s.active(cfg), "restls: active enabled with all fields");
    }

    void TestRestlsSnis(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("x.example.com"));
        auto snis = s.snis(cfg);
        runner.Check(snis.size() == 1, "restls: snis count=1");
        runner.Check(snis[0] == "x.example.com", "restls: snis[0]");
    }

    void TestRestlsSnisEmpty(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        runner.Check(snis.empty(), "restls: snis empty by default");
    }

    void TestRestlsGuess(TestRunner &runner)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        runner.Check(result.score == 100, "restls: guess score=100");
        runner.Check(result.solo_flag == 0, "restls: guess solo_flag=0");
    }

    // ─── ShadowTLS ────────────────────────────────────

    void TestShadowtlsName(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        runner.Check(s.name() == "shadowtls", "shadowtls: name");
    }

    void TestShadowtlsTier(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        runner.Check(s.tier() == 1, "shadowtls: tier=1");
    }

    void TestShadowtlsUnique(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        runner.Check(!s.unique(), "shadowtls: unique=false");
    }

    void TestShadowtlsCategory(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        runner.Check(s.category() == psm::stealth::scheme_category::facade,
                     "shadowtls: category=facade");
    }

    void TestShadowtlsActiveV3Disabled(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        runner.Check(!s.active(cfg), "shadowtls v3: active disabled by default");
    }

    void TestShadowtlsActiveV3Enabled(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 3;
        psm::stealth::shadowtls::user u;
        u.name = psm::memory::string("user1");
        u.password = psm::memory::string("pass1");
        cfg.stealth.shadowtls.users.push_back(std::move(u));
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        runner.Check(s.active(cfg), "shadowtls v3: active enabled with all fields");
    }

    void TestShadowtlsActiveV3NoUsers(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 3;
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        runner.Check(!s.active(cfg), "shadowtls v3: active disabled without users");
    }

    void TestShadowtlsActiveV2Enabled(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 2;
        cfg.stealth.shadowtls.password = psm::memory::string("v2pass");
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        runner.Check(s.active(cfg), "shadowtls v2: active enabled with all fields");
    }

    void TestShadowtlsActiveV2NoPassword(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 2;
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        runner.Check(!s.active(cfg), "shadowtls v2: active disabled without password");
    }

    void TestShadowtlsSnis(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        runner.Check(snis.size() == 2, "shadowtls: snis count=2");
        runner.Check(snis[0] == "a.example.com", "shadowtls: snis[0]");
    }

    void TestShadowtlsSnisEmpty(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        runner.Check(snis.empty(), "shadowtls: snis empty by default");
    }

    void TestShadowtlsGuess(TestRunner &runner)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        runner.Check(result.score == 100, "shadowtls: guess score=100");
        runner.Check(result.solo_flag == 0, "shadowtls: guess solo_flag=0");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("StealthFacadeSchemes");

    TestRealityName(runner);
    TestRealityTier(runner);
    TestRealityUnique(runner);
    TestRealityCategory(runner);
    TestRealityActiveDisabled(runner);
    TestRealityActivePartial(runner);
    TestRealityActiveEnabled(runner);
    TestRealitySnis(runner);
    TestRealitySnisEmpty(runner);
    TestRealityGuess(runner);

    TestRestlsName(runner);
    TestRestlsTier(runner);
    TestRestlsUnique(runner);
    TestRestlsCategory(runner);
    TestRestlsActiveDisabled(runner);
    TestRestlsActivePartial(runner);
    TestRestlsActiveEnabled(runner);
    TestRestlsSnis(runner);
    TestRestlsSnisEmpty(runner);
    TestRestlsGuess(runner);

    TestShadowtlsName(runner);
    TestShadowtlsTier(runner);
    TestShadowtlsUnique(runner);
    TestShadowtlsCategory(runner);
    TestShadowtlsActiveV3Disabled(runner);
    TestShadowtlsActiveV3Enabled(runner);
    TestShadowtlsActiveV3NoUsers(runner);
    TestShadowtlsActiveV2Enabled(runner);
    TestShadowtlsActiveV2NoPassword(runner);
    TestShadowtlsSnis(runner);
    TestShadowtlsSnisEmpty(runner);
    TestShadowtlsGuess(runner);

    return runner.Summary();
}
