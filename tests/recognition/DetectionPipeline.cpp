/**
 * @file DetectionPipeline.cpp
 * @brief 分层检测管道单元测试
 * @details 通过 mock stealth_scheme 测试 layered_detection_pipeline
 *          的构造分组、三级检测逻辑、early-out 和 native 兜底。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/stealth/recognition/pipeline.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/config/config.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string_view>

namespace
{
    // 测试用 mock scheme，可配置各层返回值
    struct mock_scheme final : psm::stealth::stealth_scheme
    {
        std::string name_;
        std::uint8_t tier_{2};
        bool active_{true};
        psm::stealth::sniff_result sniff_result_;
        psm::stealth::verify_result verify_result_;
        psm::stealth::verify_result guess_result_;

        explicit mock_scheme(std::string name, std::uint8_t tier = 2)
            : name_(std::move(name)), tier_(tier) {}

        [[nodiscard]] auto name() const noexcept -> std::string_view override { return name_; }
        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override { return tier_; }
        [[nodiscard]] auto unique() const noexcept -> bool override { return false; }

        [[nodiscard]] auto active(const psm::config & /*cfg*/) const noexcept
            -> bool override { return active_; }

        [[nodiscard]] auto sniff(std::uint32_t /*bitmap*/,
                                 const psm::stealth::hello_features & /*features*/) const
            -> psm::stealth::sniff_result override { return sniff_result_; }

        [[nodiscard]] auto verify(const psm::stealth::hello_features & /*features*/,
                                  std::span<const std::byte> /*raw*/,
                                  const psm::config & /*cfg*/) const
            -> psm::stealth::verify_result override { return verify_result_; }

        [[nodiscard]] auto guess(const psm::config & /*cfg*/) const
            -> psm::stealth::verify_result override { return guess_result_; }

        [[nodiscard]] auto handshake(psm::stealth::handshake_context /*ctx*/)
            -> boost::asio::awaitable<psm::stealth::handshake_result> override
        {
            co_return psm::stealth::handshake_result{};
        }
    };

    auto make_schemes(std::initializer_list<std::pair<std::string, std::uint8_t>> defs)
        -> std::vector<psm::stealth::shared_scheme>
    {
        std::vector<psm::stealth::shared_scheme> result;
        for (auto &[n, t] : defs)
            result.push_back(std::make_shared<mock_scheme>(n, t));
        return result;
    }

    TEST(DetectionPipeline, ConstructorTierPartition)
    {
        auto schemes = make_schemes({
            {"reality", 0},
            {"shadowtls", 1},
            {"restls", 2},
        });
        psm::recognition::layered_detection_pipeline pipeline(schemes);
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};
        // mock scheme 默认 sniff/verify 不命中，detect 应安全返回（可能空候选）
        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.deterministic_hit == false)
            << "constructor: tier partition + default mocks -> no deterministic hit";
    }

    TEST(DetectionPipeline, NativeSchemeAssignment)
    {
        auto schemes = make_schemes({
            {"reality", 0},
            {"native", 2},
        });
        psm::recognition::layered_detection_pipeline pipeline(schemes);

        // native scheme 应被识别为兜底 — 通过 tier2 空 matched_schemes 测试
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        // 有 native 兜底 → candidates 不为空
        EXPECT_TRUE(result.candidates.size() == 1) << "native assignment: 1 candidate";
        EXPECT_TRUE(result.candidates[0].name == "native") << "native assignment: name=native";
    }

    TEST(DetectionPipeline, Tier0DeterministicHit)
    {
        auto s = std::make_shared<mock_scheme>("reality", 0);
        s->sniff_result_ = {.hit = true, .solo = true, .hint = 900, .note = "session_id match"};

        psm::recognition::layered_detection_pipeline pipeline({s});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.deterministic_hit == true) << "tier0 deterministic: hit=true";
        EXPECT_TRUE(result.exclusive_scheme == "reality") << "tier0 deterministic: scheme=reality";
    }

    TEST(DetectionPipeline, Tier0NonSoloCandidate)
    {
        // tier0 non-solo + 一个 tier2 scheme（无 matched_schemes 时作为兜底）
        auto s0 = std::make_shared<mock_scheme>("reality", 0);
        s0->sniff_result_ = {.hit = true, .solo = false, .hint = 300, .note = "partial"};

        auto native = std::make_shared<mock_scheme>("native", 2);
        native->guess_result_ = {.score = 50, .solo_flag = 0, .note = "native"};

        psm::recognition::layered_detection_pipeline pipeline({s0, native});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.deterministic_hit == false) << "tier0 non-solo: deterministic=false";
        // tier0 候选在 detect() 中被丢弃，只有 tier2 native 兜底候选
        EXPECT_TRUE(!result.candidates.empty()) << "tier0 non-solo: has candidates from native fallback";
        EXPECT_TRUE(result.candidates[0].name == "native") << "tier0 non-solo: native candidate";
    }

    TEST(DetectionPipeline, Tier1DeterministicHit)
    {
        auto s0 = std::make_shared<mock_scheme>("tier0-miss", 0);
        s0->sniff_result_ = {.hit = false, .solo = false, .hint = 0, .note = ""};

        auto s1 = std::make_shared<mock_scheme>("shadowtls", 1);
        s1->verify_result_ = {.score = 800, .solo_flag = 1, .note = "hmac match"};

        psm::recognition::layered_detection_pipeline pipeline({s0, s1});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.deterministic_hit == true) << "tier1 deterministic: hit=true";
        EXPECT_TRUE(result.exclusive_scheme == "shadowtls") << "tier1 deterministic: scheme=shadowtls";
    }

    TEST(DetectionPipeline, Tier1NonSoloCandidate)
    {
        // tier1 non-solo → 不产生 deterministic hit → 进入 tier2
        // 但 tier2 无 matched_schemes，所以最终空结果
        auto s1 = std::make_shared<mock_scheme>("shadowtls", 1);
        s1->verify_result_ = {.score = 500, .solo_flag = 0, .note = "partial"};

        psm::recognition::layered_detection_pipeline pipeline({s1});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.deterministic_hit == false) << "tier1 non-solo: deterministic=false";
        // tier1 non-solo candidates 不被 detect() 传播，最终空结果
        EXPECT_TRUE(result.candidates.empty()) << "tier1 non-solo: no propagated candidates";
    }

    TEST(DetectionPipeline, Tier2WithMatchedSchemes)
    {
        auto s2a = std::make_shared<mock_scheme>("restls", 2);
        s2a->guess_result_ = {.score = 70, .solo_flag = 0, .note = "sni match"};

        auto s2b = std::make_shared<mock_scheme>("trusttunnel", 2);
        s2b->guess_result_ = {.score = 90, .solo_flag = 0, .note = "sni match"};

        psm::recognition::layered_detection_pipeline pipeline({s2a, s2b});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        // 传入 matched_schemes
        auto result = pipeline.detect(input, {s2a, s2b});
        EXPECT_TRUE(result.candidates.size() == 2) << "tier2 matched: 2 candidates";
        // 排序后高分在前
        EXPECT_TRUE(result.candidates[0].name == "trusttunnel") << "tier2 matched: sorted by score desc";
        EXPECT_TRUE(result.candidates[0].score == 90) << "tier2 matched: first score=90";
        EXPECT_TRUE(result.candidates[1].score == 70) << "tier2 matched: second score=70";
    }

    TEST(DetectionPipeline, Tier2EmptyNoNative)
    {
        auto s = std::make_shared<mock_scheme>("restls", 2);
        psm::recognition::layered_detection_pipeline pipeline({s});

        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        // 空 matched_schemes，无 native
        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.candidates.empty()) << "tier2 no native: empty candidates";
        EXPECT_TRUE(result.deterministic_hit == false) << "tier2 no native: deterministic=false";
    }

    TEST(DetectionPipeline, Tier2EmptyWithNativeFallback)
    {
        auto native = std::make_shared<mock_scheme>("native", 2);
        native->guess_result_ = {.score = 50, .solo_flag = 0, .note = "native fallback"};
        native->active_ = true;

        psm::recognition::layered_detection_pipeline pipeline({native});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.candidates.size() == 1) << "tier2 native fallback: 1 candidate";
        EXPECT_TRUE(result.candidates[0].name == "native") << "tier2 native fallback: name=native";
        EXPECT_TRUE(result.candidates[0].score == 50) << "tier2 native fallback: score=50";
    }

    TEST(DetectionPipeline, Tier2NativeInactive)
    {
        auto native = std::make_shared<mock_scheme>("native", 2);
        native->active_ = false;

        psm::recognition::layered_detection_pipeline pipeline({native});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.candidates.empty()) << "tier2 native inactive: empty candidates";
    }

    TEST(DetectionPipeline, InactiveSchemeSkipped)
    {
        auto s = std::make_shared<mock_scheme>("reality", 0);
        s->active_ = false;
        s->sniff_result_ = {.hit = true, .solo = true, .hint = 900, .note = ""};

        psm::recognition::layered_detection_pipeline pipeline({s});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.deterministic_hit == false) << "inactive skipped: deterministic=false";
    }

    TEST(DetectionPipeline, EmptyPipeline)
    {
        psm::recognition::layered_detection_pipeline pipeline({});
        psm::config cfg;
        psm::stealth::hello_features features;
        psm::recognition::detect_input input{0, features, {}, cfg};

        auto result = pipeline.detect(input, {});
        EXPECT_TRUE(result.candidates.empty()) << "empty pipeline: no candidates";
        EXPECT_TRUE(result.deterministic_hit == false) << "empty pipeline: deterministic=false";
    }
} // namespace
