# Account 模块

## 职责与边界

`Account` 拥有账户材料、凭据索引、冻结策略、配额账本和认证租约。认证成功会返回一个拥有型 `AccountLease`；协议接入把该租约移入唯一的数据面结果，后续额度和撤销事实由租约固定的 `AccountBinding` 承载。

本模块不负责协议 wire、监听器、配置解析、协议工厂或传输关闭。撤销可以封止新认证，但不会代替协议 owner 取消 I/O、完成半关闭或关闭连接。

## 关键源码

- [Account.hpp](../../../Preview/Account/Account.hpp)：账户模块聚合入口。
- [Store.hpp](../../../Preview/Account/Store.hpp)、[Binding.hpp](../../../Preview/Account/Binding.hpp)：账户快照发布及材料、策略、运行账本的不可变组合。
- [Index.hpp](../../../Preview/Account/Index.hpp)、[Authenticator.hpp](../../../Preview/Account/Authenticator.hpp)：凭据索引、scope 视图和认证入口。
- [Lease.hpp](../../../Preview/Account/Lease.hpp)、[Runtime.hpp](../../../Preview/Account/Runtime.hpp)：连接、子流与字节额度的拥有型租约及运行额度账本。
- [CredentialScope.hpp](../../../Preview/Account/CredentialScope.hpp)、[PolicyVersion.hpp](../../../Preview/Account/PolicyVersion.hpp)、[Policy.hpp](../../../Preview/Account/Policy.hpp)、[Quota.hpp](../../../Preview/Account/Quota.hpp)、[Rate.hpp](../../../Preview/Account/Rate.hpp)、[Detail/RateLedger.hpp](../../../Preview/Account/Detail/RateLedger.hpp)：稳定凭据域、策略版本、配额和共享 rate ledger。
- [Detail/LeasePool.hpp](../../../Preview/Account/Detail/LeasePool.hpp)、[Failure.hpp](../../../Preview/Account/Failure.hpp)、[SecureBytes.hpp](../../../Preview/Account/SecureBytes.hpp)：进程 root 槽、有类型的账户失败和秘密擦除。
- [AccountAssembly.hpp](../../../Preview/Application/Assembly/AccountAssembly.hpp)、[IdentityRegistry.hpp](../../../Preview/Application/Account/IdentityRegistry.hpp)：从配置准备账户材料和跨 generation 稳定身份。
- [AdmissionAuthority.hpp](../../../Preview/Contract/Account/AdmissionAuthority.hpp)、[PublicationTransaction.hpp](../../../Preview/Application/Reload/PublicationTransaction.hpp)：运行时账户成员/撤销事实与 generation publication 的边界。
- [Account README](../../../Preview/Account/README.md)：源码目录下的短入口；本页是账户合同的集中说明。

## include 与 CMake 依赖

- `Preview/` 下的生产头文件使用仓库根目录作为 include 根；`Preview/CMakeLists.txt` 将 `Account/*.hpp` 登记到 `PreviewAccount`，并令该 target 依赖 `PreviewFoundation`。
- `PreviewConfiguration`、`PreviewStreamContract`、各协议 target 与 Application 在自己的 CMake 依赖边中消费账户契约。账户实现不反向包含 Application 或具体协议装配代码。
- 账户行为测试由 [tests/Preview/Account/CMakeLists.txt](../../../tests/Preview/Account/CMakeLists.txt) 登记；应用配置和协议接入还有各自 owner 的测试目录。

## 当前数据流

1. 配置解析得到协议实例和账户配置；[AccountAssembly.hpp](../../../Preview/Application/Assembly/AccountAssembly.hpp) 按协议实例、凭据种类与 scope 冷编译账户材料。
2. [IdentityRegistry.hpp](../../../Preview/Application/Account/IdentityRegistry.hpp) 为配置候选准备稳定 `AccountId` 与 scope；[AccountStore](../../../Preview/Account/Store.hpp) 准备完整快照并在 `Commit` 时一次发布。
3. 协议 binding 持有已编译的 `CredentialIndexView` 或 `Authenticator`。热认证同步返回 typed `Failure` 或 move-only `AccountLease`，不重新解析配置或按 realm 名称查目录。
4. 协议 ingress 将获胜认证对应的 account id、身份和 lease 移入 `ProtocolDataPlane`；后续数据面使用该租约所属的材料、策略和 runtime。

## 准备、提交与稳定身份

- Application 的 identity registry 按账户名称分配并长期保留 `AccountId`；配置数组顺序不会改变它。已知名称再次出现会得到既有 id，candidate preparation 未提交时，其候选名称与 id/scope 预留会回滚。
- 同一 registry 也把协议实例 id 映射为 typed `CredentialScope`。scope 是非零数值 id；已分配 ordinal 在这个 store 生命周期内固定，store 不回收或复用 scope。
- `AccountIdentityPreparation` 的候选映射只有随 `GenerationPublication` 成功提交后才成为正式 identity 表；失败/仅校验候选销毁时会回滚名称和 scope 预留。store snapshot 的 bindings 按 `AccountId` 排序，`ForEach` 遍历该有序 snapshot，`FindById` 用 `lower_bound` 查找；Operations 账户列表用 `AccountId` 作 cursor，因此顺序和分页键一致。
- `PrepareUpsert` 接收一个完整 `AccountDefinition` 并替换该 `AccountId` 的材料/策略；`PrepareReplacement` 从完整定义集合准备一份完整候选，`PrepareRemove` 按实际 `AccountId` 生成移除候选。准备结果是 move-only `PreparedAccountUpdate`，它 pin 住 Base 与 Next；失败不发布部分 index。
- `AccountStore::Commit` 要求对同一 store 串行成功。瞬时 mutation gate 冲突返回 `Busy`，token 仍可供调用方在自己的控制 deadline 内重试；Base 与当前 snapshot 冲突或 token owner 不符返回 `Blocked`，不自动覆盖。成功只发布这个 store 的 account/index snapshot 并消费 token。
- 当前 Store 源码明确把 generation membership 和撤销提交放在 `AccountAdmissionAuthority`/publication CAS 中。`AccountStore::Commit` 本身不代表旧会话或 socket 已关闭；`Revoke` 封止新准入，实际 session drain 与 I/O close 仍归 Application/协议 owner。
- 每个新 `AccountBinding` pin 冷材料、不可变 `PolicySnapshot` 和按 `AccountId` 复用的 `AccountRuntime`。相同 account 的所有凭据 scope 共用这个 runtime；只要旧 binding、lease 或准备 owner 还 pin runtime，替换后的 binding 仍复用同一活 runtime；已有 lease 继续 pin 旧 binding/策略，策略更新不会创建第二份 quota 或 rate ledger。
- `PolicyVersion` 是独立强类型，零值无效，不是 `GenerationId`。当前 `AccountRuntimeRegistry` 为每个新 binding 分配递增版本；完整替换中每个新 definition 各取一个版本。候选准备放弃时已分配版本可能留下空隙；到 `uint64_t` 上限时返回 `VersionExhausted`，不回绕。认证请求的非零 `RequiredPolicyVersion` 可要求精确策略版本。

## 凭据索引与枚举

- `CompileScope` 在冷路径分配固定 ordinal；热路径拿 `CredentialIndexView` 后只读取一份完整 snapshot 和该 ordinal 的索引，不解析协议名、realm 名或配置数组位置。
- 每个 scope 的凭据索引按 `CredentialKind` 和 SHA-256 digest 排序，先二分定位候选范围，再以实际 credential 的 constant-time 比较确认秘密；digest 不是最终的凭据相等事实。
- `InspectCredential` 返回 `expected<bool, Failure>`：`true` 是匹配、`false` 是纯 miss、`unexpected` 是输入/哈希等错误。它不取账户 lease、不预约连接/stream quota，也不消耗 rate。
- `TryAcquire` 同步借用 `CredentialView` 和 identity；请求可附 `AccountId` 与 `RequiredPolicyVersion`。唯一匹配后依次申请 process root slot、账户 admission/连接额度和 rate reservation，最后重查 store 准入再提交 rate 与 admission permit；任何中途失败都会通过 owning RAII token 回滚已取得的资源。identity、display name 和 policy 事实由获胜 lease 的唯一 binding 派生。
- `ForEachCredential` 仅用于冷枚举：同步 visitor 收到 `AccountBinding` 与 `CredentialMaterial` 两项，当前 snapshot 在整个回调期间保活。不得保存借用材料跨异步边界；异步使用应 pin 对应的 binding。

## 凭据 identity 消歧义

不同的非空 identity 可以共享同一 scope 下的凭据。请求没有提供 identity 时，只能在该凭据唯一命中时认证；多身份共享凭据时，必须由请求 identity 消歧。凭据材料的 identity 为空时，可以匹配带 identity 的请求；但空 identity 通配不得与同一秘密的命名 identity 造成歧义。

## 所有权、错误与关闭

- `PrepareUpsert`、`PrepareReplacement`、scope 编译和 `Commit` 是控制面的同步冷路径；提交采用完整快照，不在失败时发布部分认证事实。
- 凭据视图返回 `std::expected`/`Preview::Fault::Failure`；认证失败、取消、配额不足和资源不可用是显式领域错误。
- `AccountLease`、`StreamLease`、`ByteLease` 是拥有型配额/准入票据。释放会归还账户侧资源或关闭后续准入；协议 session、stream、UDP association 或 mux root 仍是实际 I/O 的取消者与最终关闭者。
- Account 本身不拥有 executor、stream half-close 或 socket。业务 owner 需先按自己的生命周期契约排空，再退休相应统计或账户运行范围。

### Root、child 与字节额度

- `AccountLease` 是 move-only 根 lease，固定 pin `AccountBinding` 和进程级 `LeasePool` 槽。`Release` 原子封止该 root 的后续 child 准入，不关闭 socket；已取得 child 仍持有 parent root。连接额度在 root 已封止且最后一个 child 退出后归还。
- `StreamAdmission` 是 root 派生的窄 child 能力；它只 pin 同一个 root slot，不复制 root connection quota 或重新认证。取得 `StreamLease` 要同时通过账户 publication 准入、冻结 `MaxStreams` quota 与 root child gate；lease release 精确归还 stream quota/child 计数。
- `ByteLease` move-only 地 pin binding 和它实际取得的字节数；额度依照该 binding 的冻结 `QuotaPolicy::MaxBytes`。析构/`Release` 只归还本 lease 持有的字节；`Reduce` 超过本 lease 已有量会拒绝，不动其他 owner 的额度。quota 值 `0` 表示该项业务上限未启用。
- `AccountRuntime` 只保存账户 admission/连接、stream、byte 与 rate 账本，不拥有 executor 或 I/O。Revoke 改变账户准入事实；协议 owner 负责 cancel、半关闭、任务 drain、最终 socket close，再释放对应 lease。

### Rate ledger 与策略更新

- 同一 `AccountRuntime` 拥有唯一 `RateLedger`。每个 `RateLimiter`/策略版本是该账本上的冻结 view；更新策略会创建新 view，不会创建第二本消费账或把窗口用量清零。
- `UnlimitedRatePolicy`、`StrictGlobalRatePolicy` 和 `WorkerShardedRatePolicy` 是当前三种策略。StrictGlobal 在所有 worker 间共用限额；WorkerSharded 使用每 worker `ceil(global / count)` 限额，最大合计超量由 `PerWorkerLimit`/`MaxOvershoot` 明确给出。`StoreOptions::WorkerCount` 冷冻结；Application 装配应传真实 worker 数，rate policy 的 worker 数不得超出它。
- 一个新 view 继承仍在同一时间窗口内的旧用量。每个成功的 reservation commit 会向 ledger 中仍被 pin 的策略 view 同时记入真实单位；放弃 reservation 不消费单位。这样旧 lease 固定旧策略时，也不会与新策略在共享 runtime 上重复消费同一额度。
- `RateReservation` 是同步、短期、不可跨 `co_await` 的一次 gate reservation。竞争返回 `Busy`/`ResourceUnavailable`，限额耗尽则返回 `RateLimited`（映射为 `WouldBlock`）；二者不混为一类，也不在账户热路径等待竞争者。
- 每个 ledger 最多保留 8 个仍被 owner pin 的 policy view；满时新策略准备返回 `PolicyViews`，不会强行释放旧 binding/lease。受限速率必须提供非零且不回退的 `Now`；Unlimited 可使用账本已有时间，初始无时间时记录 `1ms`，不读取系统时钟。

## 容量与错误语义

下表是当前构造选项/owner 的源码值，不是当前实例已经分配到的数量：

| 资源 | 当前默认值与限制 | 满/无效时的表现 |
| --- | --- | --- |
| 账户身份与 runtime 登记 | identity/runtime 登记最多 4096 个；`StoreOptions::MaxAccounts` 默认 4096，构造上限 4096 | `Accounts`/`ResourceUnavailable` 或输入无效 |
| root lease 槽 | 默认 4096；`RootLeaseSlots` 可配置至 65536；槽位需等最后元数据/child 引用退出才归还 | `RootSlots`，立即失败，不等待空槽 |
| 凭据输入与 identity | store 默认最多 64 KiB；选项硬上限 1 MiB，材料与请求 identity 都受该 store 值限制 | `OversizedMsg` 或无效凭据 |
| typed credential scope | 每个 store 最多 64 个非零 scope，ordinal 生命周期内不复用 | `Scopes`/`ResourceUnavailable` |
| worker 维度 | `WorkerShardedRatePolicy::MaxWorkerCount` 为 4096；store 冷配置的 worker 数须在范围内 | `InvalidArgument` |
| rate policy view | 每个 ledger 最多 8 个仍存活的 view | `PolicyViews`/`ResourceUnavailable` |
| stream/byte quota | 由 binding 冻结的 `MaxStreams`/`MaxBytes` 控制；账户层 root child 计数不另设固定 128 槽 | `StreamQuota` 或 `ByteQuota`；协议/mux/task owner 还可施加自己的真实容量边界 |

账户失败保留 `Preview::Fault::Failure` 的 code 和 `Preview.Account` error category/value，业务判断不应解析 message 文本。当前常见映射为：`Revoked` → `Forbidden`，`RateLimited` → `WouldBlock`，`InvalidCredential` → `InvalidArgument`，`NotFound` → `AuthFailed`，`PolicyMismatch` → `Blocked`；quota、busy、root slot、scope/account 容量和 policy-view/version exhaustion 等仍有独立账户 reason 值。构造无效 `StoreOptions`、`Credential` 或 root pool capacity 会抛 `std::invalid_argument`；热认证/额度操作用 `expected`/typed failure，租约释放为 `noexcept`。

凭据由 move-only `Credential`/`SecureBytes` 拥有；`CredentialView` 只借用到同步返回。`SecureBytes` 清理时使用 `Crypto::SecretScope`/`OPENSSL_cleanse` 擦除缓冲区，公开描述固定为脱敏文本。

## 配置支持、生产接线与运行证据

- **模型与配置准备：** [ProtocolConfiguration.hpp](../../../Preview/Contract/Ingress/ProtocolConfiguration.hpp) 定义协议实例 id、builtin 和承载绑定；账户配置由 Application 配置模型提供，AccountAssembly 将其转换为 typed 材料与 scope。
- **生产接线：** [ProviderAssembly.hpp](../../../Preview/Application/Assembly/ProviderAssembly.hpp) 将已准备 generation 和服务传入 Composition；真实协议的 Prepare 分支消费账户认证服务。配置存在本身不表示有 provider 实现，具体实现槽由 Composition 的 provider catalog 决定。
- **运行证据边界：** 本页只列源码接线与测试映射，不登记 build、CTest、运行或互操作结果；通过结论只能来自绑定当次源码、配置和 binary hash 的验收报告。本页不声称通过。

## 测试位置

- [tests/Preview/Account](../../../tests/Preview/Account/)：账户凭据、lease、rate policy、目录 reload 和 authenticator 测试，具体注册见该目录的 `CMakeLists.txt`。
- [tests/Preview/Application/Configuration](../../../tests/Preview/Application/Configuration/)：配置装配与 generation 边界。
- [tests/Preview/Integration/Session](../../../tests/Preview/Integration/Session/)：从真实协议 session 检查账户接入的集成场景。
