# Preview Diagnose Baseline

Date: 2026-09-26
TaskCard: A - Baseline and exact scope
Status: HANDOFF_ACCEPTED

## Workspace State

- Repository: `I:/code/Prism`
- Branch: `main`
- HEAD: `a4fb25e9` (`2026-09-21 21:15:53 +0800`, `让 Preview 配置矩阵更完整`)
- Tracked diff: none
- Existing untracked input: `docs/preview-refactor/2026-09-26-preview-diagnose-header-only-plan.md`; preserve it as user input.
- Existing `build/CMakeCache.txt`: present. No build or test was run during this baseline.

## Existing Diagnose Surface

| File | Current responsibility |
|---|---|
| `Preview/Foundation/Utility/Diagnose/Context.hpp` | Mutable shared `TraceContext`, `TraceSnapshot` selection, mutable string fields |
| `Preview/Foundation/Utility/Diagnose/Log.hpp` | Owner-aware submission wrappers plus legacy ownerless no-op overloads |
| `Preview/Foundation/Utility/Diagnose/Logger.hpp` | Custom thread, mutex/deque queue, file rotation, formatting, per-message redaction, lifecycle |
| `Preview/Foundation/Utility/Diagnose/Observability.hpp` | Histogram, EWMA, sampling; independent of logger migration |

`Logger::TryWrite()` formats and redacts a message on the submitting thread, then copies it into an in-process deque. It specially locks and deduplicates `Access` records whose event is `session_closed`; the source comment calls these lifecycle audit records. `Runtime/Session.hpp` emits the close record, and `LoggerTest.cpp` covers exactly-once close behavior. Migrate this event to the explicit `Audit` semantic; normal `Access` remains droppable.

## Call-Site Manifest

The following files contain direct Diagnose includes, owner state, submissions, or ownerless log calls. They form the initial migration manifest; any new matches found during implementation must be added here and reviewed before editing.

| Task group | Files |
|---|---|
| E1 Application / Runtime | `Preview/Application/Application.cpp`, `Preview/Runtime/Session.hpp`, `Preview/Runtime/SessionServices.hpp`, `Preview/Runtime/Middleware/Builtin/Relay.hpp` |
| E1 Application admissions | `Preview/Application/TuicAdmission.hpp` |
| E2 Composition / MUX | `Preview/Composition/Adapters/ProtocolAdapter.hpp`, `Preview/Composition/Adapters/Socks5.hpp`, `Preview/Protocols/Mux/Session.hpp` |
| E3 Ingress / QUIC | `Preview/Ingress/QuicAdmissionContext.hpp`, `Preview/Composition/Quic/Hysteria2Factory.hpp`, `Preview/Composition/Quic/TuicFactory.hpp` |
| E4 Transport | `Preview/Transport/Encrypted.hpp`, `Preview/Transport/Preview.hpp`, `Preview/Transport/Reliable.hpp`, `Preview/Transport/Unreliable.hpp` |
| E4 Protocols | `Preview/Protocols/Common/Address.hpp`, `Preview/Protocols/Http3/Session.hpp`, `Preview/Protocols/Xhttp/Conn.hpp` |
| Diagnose implementation | `Preview/Foundation/Utility/Diagnose/Context.hpp`, `Log.hpp`, `Logger.hpp`; retain `Observability.hpp` |

`Preview/Runtime/Listener.hpp` has no direct Diagnose include or call in the search inventory. Worker identity is assembled through Application/runtime identity flow; verify the exact WorkerContext creation point while migrating E1 rather than adding an unrelated Listener log call.

## Configuration and Compatibility

- `PreviewConfiguration.hpp` defines `LoggingConfiguration` with Level, Directory, FileName, Console, RotateBytes, RotateFiles, and FlushIntervalMs. `TraceConfiguration` defaults IncludeCorrelation/IncludeWorker/IncludeSession to true and IncludeStream to false.
- `PreviewConfigurationJson.hpp` serializes the Logging and Trace fields. `PreviewConfiguration.json` has no RenderMode field and currently sets IncludeCorrelation true.
- `ConfigurationValidator.hpp` validates logging level, directory, filename, rotation, and FlushIntervalMs (1..600000 ms). Preserve FlushIntervalMs and make a missing RenderMode default to CompactHuman; reject unknown RenderMode values.
- Relevant tests are `tests/Preview/core/Configuration/ConfigurationTest.cpp`, `tests/Preview/core/diagnose/LoggerTest.cpp`, `ObservabilityTest.cpp`, and the Preview Application tests. `AddPreviewTest()` creates one executable per `.cpp` and uses PRE_TEST GoogleTest discovery. There is no Diagnose test fixture under `tests/TestSupport/Preview` yet.

## CMake and Dependency Boundary

- `PreviewFoundation` is an INTERFACE target and currently lists Context.hpp, Logger.hpp, Observability.hpp, and Log.hpp.
- `PreviewApplication` is a STATIC target compiling `Preview/Application/Application.cpp`; it links the Preview targets publicly and currently owns the Application lifecycle.
- `Preview/CMake/PreviewBoundary.cmake` validates Preview dependencies, sources, include closures, and the standalone PrismPreview closure. Extend its explicit Application dependency allowlist only for a justified private backend dependency.
- Root CMake FetchContent provides spdlog 1.17.0. `src/prism/diagnose/CMakeLists.txt` adds `spdlog.cpp` to `PrismStaticLibrary`; there is no separate narrow `PrismDiagnose` target in the current CMake source. Preview must not link `PrismStaticLibrary` or production include paths.
- Production owner bridge target/file chosen by the accepted plan: `Preview/Application/DiagnoseRuntime.hpp`, private to `PreviewApplication`. Backend Detail headers must be privately compiled through this owner. Each backend test executable owns one test environment through `tests/TestSupport/Preview/DiagnoseTestEnvironment.hpp`.

## Ordered Dependencies

| Card | Required output | Unlock condition |
|---|---|---|
| A | This baseline and call-site manifest | Coordinator confirms file scope |
| B | Immutable Context, field descriptors/codecs, typed tests | B tests and size/capacity contract reviewed |
| C | Owned record snapshot and renderers | Context/decoder/lifetime tests reviewed |
| D | Single backend owner, private startup bridge, lifecycle tests | Queue/fallback/shutdown tests and CMake owner boundary reviewed |
| E1-E5 | Per-group migration from the manifest | Each group reviewed before the next group |
| F | RenderMode schema and final target closure checks | All migration groups reviewed |
| G | Regression, benchmarks, evidence and cleanup | Final build/test evidence and coordinator review |

## Execution Progress

| TaskCard | Status | Evidence |
|---|---|---|
| A | `HANDOFF_ACCEPTED` | Baseline and manifest reviewed; tracked source remained untouched. |
| B | `VERIFIED` | `TraceContextTest` and `FieldCodecTest` built in `build/` Release with `-j 1`; `ctest --test-dir build -R PreviewDiagnose --output-on-failure -j 1` passed 7/7. |
| C | `VERIFIED` | `ContextDecoderTest` and `ContextLifetimeTest` built in `build/` Release with `-j 1`; `ctest --test-dir build -R PreviewDiagnose --output-on-failure -j 1` passed 11/11. |
| D | `VERIFIED` | Five backend targets built in `build/` Release with `-j 1`; `ctest --test-dir build -R PreviewLogger --output-on-failure -j 1` passed 14/14. CMake configure passed with `PreviewApplication` as owner. |
| E1 | `HANDOFF_ACCEPTED` | `PreviewApplication`, Session/Relay targets and `SessionAuditTest` built in `build/` Release with `-j 1`; focused CTest passed 49/49 across the runtime/relay group and the two `G2Log` failure-isolation cases. Structured output contained exactly one `event=session_closed`; missing-backend failure and shutdown paths passed. |
| E2 | `HANDOFF_ACCEPTED` | `PreviewApplication`, Session and `MuxSessionTest` targets built in `build/` Release with `-j 1`; focused CTest passed 58/58 across Session Recognition/Orchestration and MUX. The three manifest headers now use Facade and explicitly discard ordinary receipts. |
| E3 | `HANDOFF_ACCEPTED` | `PreviewApplication`, Hysteria2/TUIC factory and startup targets built in `build/` Release with `-j 16`; focused CTest passed 6/6 across Hysteria2 factory, TUIC factory, TUIC startup and Session diversion. |
| E4 | `HANDOFF_ACCEPTED` | `PreviewApplication`, Transport, NativeHttp3Session and XhttpErrorMatrix targets built in `build/` Release with `-j 16`; focused CTest passed 72/72. TLS/nghttp3 error text is redacted before formatting. |
| E5 | `HANDOFF_ACCEPTED` | Legacy Context/Logger/Log headers, public registrations and temporary include-order marker are removed. Diagnose, backend, Logger integration and Task10 targets built; focused CTest passed 36/36 and the old API reference scan returned zero. |
| F | `HANDOFF_ACCEPTED` | PreviewApplication, ConfigurationTest and PrismPreview built in `build/` Release with `-j 16`; focused CTest passed 50/50. CMake assertions passed and generated `build/preview-diagnose-target-closure.txt`. |
| G | `HANDOFF_ACCEPTED` | Final serial CTest passed 387/387; Compact/Extended performance CTest passed 3/3. Retained JUnit, three performance JSON files, three output samples, target closure report, hashes, and cleanup evidence are indexed in `2026-09-26-preview-diagnose-final-evidence.md`. |

Ruling: In HumanWithFields and Structured, the legacy IncludeWorker/IncludeSession flags select expanded Worker/Session fields while the fixed identity prefix/top-level values remain present. This preserves the accepted plan's expanded selection behavior; the cost if wrong is duplicate Worker/Session identifiers in those opt-in modes.

Ruling: JSON control bytes use the valid `\\u00XX` escape form, and each JSON Lines record ends with one LF terminator. Tests distinguish message escaping from the record separator; the cost if wrong is only a different valid JSON escape spelling, not a change to decoded message values.

Ruling: Use a project-owned bounded ring plus one backend worker feeding synchronous spdlog sinks. `spdlog::async_logger` does not expose the per-level enqueue outcome needed for ordinary drops versus Warn/Error/Audit fallback; the custom ring makes those receipts testable. The cost is maintaining the ring and its lifecycle alongside spdlog.

Ruling: Keep spdlog's native rotated filename convention (`preview.1.log`) while keeping `Logging.FileName` as the active file. The previous custom logger used `preview.log.1`; the plan requires rotation behavior but not that suffix. The cost if wrong is updating any external tooling that names rotated files directly.

Task D CMake note: `spdlog::spdlog` is private on `PreviewApplication`; CMake's static link closure still reports it as a link-only dependency of `PrismPreview`. `PreviewFoundation` and Preview business INTERFACE targets do not link it. Task F must report compile/include closure separately from final link closure and allow only this backend-owner exception.

E1 ruling: Session starts from the value-owned `SessionServices::ProcessContext`, then derives Worker/Session prefix identities and Task/Generation fields. TaskId is not represented as Correlation; the recognition message now names it `task_id`. This corrects the former misleading label while preserving the identity value.

E1 ruling: Stage/Status per-call fields use `TryWith`; larger recognition snapshots use owned `With` values and sensitive NativeError is redacted by its descriptor. Context construction, formatting and receipt failure are caught or ignored so they cannot change Session results. Session close keeps an immutable identity-only audit context and an atomic final fault code because cancellation close callbacks can race with Run completion.

E1 test boundary: `SessionOrchestrationTest` has no backend owner and verifies Session results/close behavior with a stopped facade. `SessionAuditTest` is a backend-owned test executable using `DiagnoseTestEnvironment`; it drains the backend before reading JSONL and verifies exactly-once close output and identity fields.

E1 include-order finding, resolved in E5: while the old compatibility header remained, mixed translation units required Facade-first include order and a temporary marker in `Log.hpp`. E5 removes that marker together with `Log.hpp`, `Context.hpp` and `Logger.hpp`; surviving modules now include Facade directly.

E1 verification note: CMake configure and the requested targets passed. At that checkpoint, compilation still reported ignored receipt warnings from E4 no-context callsites; E4 now explicitly discards those ordinary receipts.

E2 ruling: ProtocolAdapter, SOCKS5 Adapter and MUX warnings are ordinary diagnostics; each now uses compile-time Facade formatting and explicitly ignores its receipt. No warning receipt is read by protocol or MUX control flow.

E3 manifest adjustment: `TuicFactory.hpp` directly includes `QuicAdmissionContext.hpp`; its standalone test target exposed the same old/new log header collision. It is added to E3 as an include-boundary owner, with no TUIC factory behavior change.

E3 ruling: Hysteria2/TUIC relay callbacks derive Carrier/Protocol with inline `TryWith` bindings and capture the shared admission owner alongside the value Context. This keeps borrowed protocol text alive through synchronous Facade submission; the backend receives its owned snapshot before the callback returns. Context-capacity or capture failure falls back to the admission base Context and never changes dial/relay control flow.

E4 ruling: Native TLS and nghttp3 diagnostic strings pass through `RedactSensitiveText` before compile-time Facade formatting; allocation/redaction exceptions are contained in the logging branch. Reliable, Unreliable and Common Address had stale Log.hpp includes but no log calls, so those includes were removed without adding a replacement dependency.

E5 ruling: `LoggerTest` remains as one `PreviewLogger` integration test backed by `DiagnoseTestEnvironment`; old queue, fallback, rotation, shutdown, field codec and exactly-once behaviors are covered by the dedicated backend/Context/Session tests. Legacy epoch-file archival is covered by the backend initialization test when switching to Structured mode.

E5 lifecycle fix: `SinkSet::ArchiveMismatchedFile` closes its `ifstream` before renaming a mismatched file. Windows rejects rename while the read handle remains open; `PreviewLogger.InitializationRejectsDirectoryFailureAndConflictingConfig` now verifies the prior-format file is archived and preserved.

F configuration ruling: `Logging.RenderMode` is a strictly case-sensitive string at the JSON boundary; omission keeps the model default `CompactHuman`, and the shipped Preview configuration sets that value explicitly. The Application bridge maps only the three validated names to the Diagnose enum.

F CMake ruling: `AssertPreviewDiagnoseBackendBoundary` checks that `PreviewApplication` owns a private spdlog link, no Preview business target exposes spdlog link/include properties, and writes `build/preview-diagnose-target-closure.txt`. The final PrismPreview closure contains spdlog as the expected static link-only dependency.

G benchmark ruling: each path used 10,000 warmup submissions and five 20,000-submission samples at 128 B, 512 B and 2 KiB message payload sizes. The measured 8,192-entry queue reached high-water in each scenario and recorded Info drops; this is retained as the first baseline, with no previous performance JSON or numeric regression threshold available for comparison.

## Baseline Snapshot Boundary

The read-only statements above describe the state captured before implementation. They are retained as historical baseline evidence; final implementation verification is recorded in [the final evidence report](2026-09-26-preview-diagnose-final-evidence.md).

## Final Coordinator Review

G is HANDOFF_ACCEPTED. The final serial CTest run passed 387/387 with zero failures or errors, including all three performance tests. The benchmark output records queue saturation and Info drops as the first measured baseline; no earlier performance artifact or numeric regression threshold was available. The final evidence report indexes the raw JUnit XML, performance JSON, output samples, target closure report, SHA-256 values, and cleanup observations.
