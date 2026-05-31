## 交叉引用

- `crypto-audit` 覆盖了本 skill 未深入探讨的 AEAD 密钥管理、HKDF 密钥派生、常量时间操作、证书与签名维度
- `probe-audit` 覆盖了本 skill 未深入探讨的回落机制形式化安全、跨协议探测防御、多阶段探针协调维度
- `leak-audit` 覆盖了本 skill 未深入探讨的错误响应格式指纹、日志泄漏、部署规模追踪维度

## 审计流程

### 第一步：识别认证路径

确定协议的所有认证入口点和认证流程。绘制从"连接建立"到"认证完成"的完整代码路径，标注每一步的安全检查点。特别关注：
- 首包读取和解析的入口
- 密码/令牌的验证函数
- 认证成功后的状态转换
- 认证失败后的回落路径

### 第二步：枚举攻击向量

列出审查系统可能发送的所有探针类型：
- **即时重放**：捕获合法认证包后立即重放（同一会话或新会话）
- **延迟重放**：数小时或数天后重放捕获的包
- **篡改重放**：修改捕获包的某些字节后重放
- **256 变体攻击**：对每个字节位置尝试 256 种值
- **乱码数据**：发送随机二进制数据
- **协议混淆**：发送其他协议格式的数据
- **分区探针**：多用户场景下尝试区分不同用户

### 第三步：验证时间戳防御

确认时间戳校验覆盖所有认证路径：
- 时间戳是否包含在加密保护的载荷中？
- 服务端时间窗口是否合理（推荐 ±30 秒）？
- 是否容忍时钟偏移？
- 窗口内的重放是否有 nonce 记忆作为第二道防线？

### 第四步：验证 Nonce 防御

确认 nonce 管理的完整性：
- Nonce 唯一性保证（计数器原子递增、无回绕）
- 方向隔离（独立的 C→S 和 S→C 计数器）
- 溢出处理（拒绝新连接而非回绕）
- UDP 显式 nonce（不依赖隐式递增）
- **Nonce 记忆持久性**：是否覆盖延迟重放窗口（至少 72 小时）？记忆池的实现是否使用时间窗口滑动缓存？

### 第五步：验证选择密文攻击防御

确认 AEAD 对所有篡改密文的一致拒绝行为：
- 所有加密通道是否使用 AEAD？
- Tag 验证是否在解密前执行？
- 解密失败行为是否与正常处理一致（时间、资源、响应内容）？
- 256 变体攻击是否被一致拒绝？

### 第六步：验证多用户分区防御

确认多用户场景下的认证失败行为一致性：
- 所有用户的认证失败响应是否完全相同？
- 多用户匹配的时间是否恒定？
- 是否避免了用户标识泄漏？
- 是否考虑了单用户单端口架构？

### 第七步：验证重放响应行为

确认重放被拒绝后的响应行为与标准 Web 服务器一致：
- 响应长度是否与正常代理响应混淆？
- 是否模拟了标准 Web 服务器的行为（而非返回空响应或断开）？
- 响应时间分布是否与正常请求一致？
- 响应内容是否包含合理的 Web 内容？

## 常见反模式（禁止）

### AEAD 与加密

```cpp
// ❌ 流加密无认证 — 选择密文攻击
// 审查者发送 256 个连接，每个改变一个字节
// 某个连接碰巧使得服务端不立即断开 → 确认是代理
aes_cfb_encrypt(key, nonce, plaintext);

// ✅ AEAD 认证加密 — 密文完整性保证
// 任何一位翻转都导致 tag 验证失败
aead_context ctx(aead_cipher::aes_128_gcm, key);
ctx.seal(out, plaintext, ad);

// ❌ Nonce 重复 — 彻底破坏 AEAD 安全性
// AES-GCM: 2 次复用即可恢复认证子密钥 H
std::uint8_t nonce[12] = {0};  // 固定 nonce，每次加密都相同

// ✅ 计数器型 nonce + 溢出检测
std::uint8_t nonce[12];
auto ctr = encode_be<std::uint64_t>(sequence_number++);
if (sequence_number == 0)
{
    // 溢出，必须拒绝加密
    return fault::code::nonce_exhausted;
}
memcpy(nonce + 4, ctr.data(), 8);

// ❌ Nonce 回绕 — 灾难性安全失效
sequence_number = 0;  // 重置为 0，与初始 nonce 重复

// ✅ 溢出时拒绝新连接
if (sequence_number > MAX_SEQUENCE)
{
    return fault::code::nonce_exhausted;
    // 不回绕，拒绝此连接
}
```

### 时间戳防重放

```cpp
// ❌ 无时间戳 — 认证数据可被无限期重放
auto hash = sha224(password + salt);
// hash 值永远不变，审查者可以数年后重放

// ✅ 时间戳绑定 — 限制重放窗口
auto hash = sha224(password + salt + timestamp);
if (abs(now - timestamp) > 30s)
{
    co_await fallback_dest(raw_request);  // 静默回落
}

// ❌ 仅检查"不早于" — 忽略未来时间戳
if (timestamp < now - 30s)
{
    reject();  // 过去的时间戳拒绝
}
// 未来时间戳未检查 → 攻击者可预生成未来时间戳的包

// ✅ 双向窗口检查
if (timestamp < now - 30s || timestamp > now + 30s)
{
    co_await fallback_dest(raw_request);
}

// ❌ 时间戳在明文中 — 可被篡改
send(ciphertext || timestamp);  // timestamp 未加密

// ✅ 时间戳在加密保护范围内
auto payload = encrypt(plaintext || timestamp, key, nonce, ad);
```

### Nonce 记忆持久化

```cpp
// ❌ Nonce 仅在单次会话内记忆 — 无法防御延迟重放
// 会话结束即清空 nonce 历史
// 审查者在会话结束后重放 → nonce 不在历史中 → 被接受
struct session
{
    std::set<std::uint64_t> used_nonces;  // 随 session 销毁
};

// ✅ 跨会话的 nonce 记忆池 — 时间窗口滑动缓存
// 72 小时窗口的环形缓冲区
struct nonce_cache
{
    // 按时间桶组织，每个桶覆盖 1 小时
    // 每条目：nonce(16B) + timestamp(8B) = 24B
    // 1000 连接/天 × 72h × 24B ≈ 1.7 MB
    std::unordered_map<std::uint64_t, time_bucket> buckets;

    [[nodiscard]] auto record_nonce(span<const std::uint8_t> nonce)
        -> bool
    {
        auto now = steady_clock::now();
        auto ts = now.time_since_epoch().count();
        auto bucket_id = ts / 3600;  // 每小时一个桶

        // 淘汰过期桶（超过 72 小时）
        prune_old(bucket_id - 72);

        auto& bucket = buckets[bucket_id];
        auto [it, inserted] = bucket.insert({nonce, now});
        return inserted;  // false = nonce 重复 = 重放
    }
};

// ❌ Nonce 缓存无限增长 — 内存耗尽
std::set<std::vector<std::uint8_t>> past_nonces;  // 永不清空

// ✅ 时间窗口淘汰策略
void prune_old(std::uint64_t threshold)
{
    for (auto it = buckets.begin(); it != buckets.end(); )
    {
        if (it->first < threshold)
        {
            it = buckets.erase(it);  // 自动释放内存
        }
        else
        {
            ++it;
        }
    }
}
```

### 首包与密码认证

```cpp
// ❌ 固定读取最大长度 — 阻塞或过度读取
remaining = ulen + 1 + 255;  // 即使密码只有 8 字节
co_await recv_impl(buffer(remaining), ec);

// ✅ 分步精确读取
co_await recv_impl(buffer(ulen + 1), ec);  // UNAME + PLEN
auto plen = buf[2 + ulen];
co_await recv_impl(buffer(plen), ec);       // 仅读取实际密码长度

// ❌ 明文密码比较 — 非常量时间
if (std::string_view(received) == expected_password)
{
    ...
}
if (memcmp(received.data(), expected.data(), len) == 0)
{
    ...
}

// ✅ 哈希后常量时间比较
auto received_hash = sha224(received);
auto expected_hash = sha224(stored_password);
if (CRYPTO_memcmp(received_hash.data(), expected_hash.data(),
                  received_hash.size()) == 0)
{
    ...
}

// ❌ 认证失败直接断开 — 暴露代理
if (!authenticated)
{
    transport_->close();
}

// ✅ 认证失败返回标准错误或回落到真实 Web 服务
if (!authenticated)
{
    co_await fallback_dest(session, raw_request);
}

// ❌ 首包无时间维度 — 可被无限期重放
auto auth_data = password_hash || target_address;
// 完全相同的 auth_data 可被无限重放

// ✅ 首包绑定时间戳和 nonce
auto auth_data = password_hash || timestamp || client_nonce || target_address;
// timestamp 限制重放窗口，nonce 防止窗口内重复
```

### 多用户分区攻击

```cpp
// ❌ 多用户认证行为不一致 — 分区预言攻击
for (auto& user : users)
{
    auto decrypted = try_decrypt(received, user.key);
    if (decrypted.has_value())
    {
        return handle_user(user, *decrypted);
    }
}
// 不同用户解密成功/失败的行为不同

// ✅ 统一认证失败行为
bool authenticated = false;
for (auto& user : users)
{
    auto decrypted = try_decrypt(received, user.key);
    if (decrypted.has_value() && validate_payload(*decrypted))
    {
        authenticated = true;
        // 不立即返回，继续遍历以保持恒定时间
    }
}
if (!authenticated)
{
    co_await fallback_dest(raw_request);  // 统一回落行为
}

**注意**：此方法仍通过总遍历时间泄露用户数量（始终遍历 N 个用户）。当多个用户共享同一端口和协议时，无法完全防御分区预言攻击。最有效的缓解是单用户单端口部署。

// ❌ 用户数量影响响应时间
for (auto& user : users)
{       // 遍历 N 个用户
    if (match(user))
    {
        return ok;
    }   // 找到匹配立即返回
}
// 未找到匹配 → 遍历了所有 N 个用户 → 响应时间更长

// ✅ 遍历时间恒定
bool found = false;
for (auto& user : users)
{
    // 始终遍历所有用户，不提前退出
    if (match(user) && !found)
    {
        found = true;
        selected = &user;
    }
}
```

### 重放响应行为

```cpp
// ❌ 重放被拒绝后返回空响应 — 行为异常
if (is_replay(nonce))
{
    co_return;  // 空响应，与正常 Web 服务器行为不一致
}

// ✅ 重放被拒绝后模拟标准 Web 服务器行为
if (is_replay(nonce))
{
    co_await fallback_dest(raw_request);  // 转发到真实网站
}

// ❌ 重放检测有快速路径 — 时序侧信道
if (nonce_cache.contains(nonce))
{
    close();  // 立即关闭，响应时间极短
}
// 正常路径：解密 → 解析 → 建立连接 → 转发 → 响应（数百 ms）
// 重放路径：查表 → 关闭（< 1 ms）
// 时间差 100 倍以上，极易被测量

// ✅ 重放检测路径时间与正常路径一致
if (nonce_cache.contains(nonce))
{
    // 添加与正常路径等量的延迟
    co_await fake_delay();
    co_await fallback_dest(raw_request);
}

// ❌ 重放拒绝返回固定长度短响应 — 可识别
if (is_replay(nonce))
{
    co_await send(fake_response);  // 每次都是 200 字节
}

// ✅ 重放拒绝通过回落到真实 Web 服务器获得自然的响应长度
if (is_replay(nonce))
{
    co_await fallback_dest(raw_request);
    // 真实 Web 服务器的响应长度自然多样
}
```
