import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const scannerPath = path.join(projectRoot, "scripts", "check_prism_reachability.mjs");

function writeFile(root, relativePath, content) {
  const filePath = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
}

function createFixture(t, testCMake, extraTestFiles = []) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "prism-reachability-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "scripts"), { recursive: true });
  fs.copyFileSync(scannerPath, path.join(root, "scripts", "check_prism_reachability.mjs"));
  writeFile(root, "Include/Prism/Probe.hpp", "#pragma once\n");
  writeFile(root, "Src/Prism/Probe.cpp", "int Probe() { return 0; }\n");
  writeFile(root, "Src/Prism/CMakeLists.txt", [
    "set(PROBE_HEADERS ${PROJECT_SOURCE_DIR}/Include/Prism/Probe.hpp)",
    "set(PROBE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/Probe.cpp)",
    "PrismAddStaticTarget(Prism HEADERS ${PROBE_HEADERS} PRIVATE_HEADERS ${PROJECT_SOURCE_DIR}/Src/Prism/Detail/Private.hpp SOURCES ${PROBE_SOURCES})",
    "include(CMake/PrismLinks.cmake)",
  ].join("\n"));
  writeFile(root, "Src/Prism/CMake/PrismLinks.cmake", [
    "target_link_libraries(Prism PUBLIC PrismFoundation)",
    "target_sources(Prism PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Included.cpp ${CMAKE_CURRENT_LIST_DIR}/IncludedList.cpp)",
  ].join("\n"));
  writeFile(root, "Src/Prism/Included.cpp", "int Included() { return 1; }\n");
  writeFile(root, "Src/Prism/CMake/IncludedList.cpp", "int IncludedList() { return 2; }\n");
  writeFile(root, "Src/Prism/Detail/Private.hpp", "#pragma once\n");
  writeFile(root, "tests/Prism/FirstTest.cpp", "TEST(Probe, First) {}\n");
  writeFile(root, "tests/Prism/SecondTest.cpp", "TEST(Probe, Second) {}\n");
  writeFile(root, "tests/TestSupport/CMakeLists.txt", [
    "add_library(PrismTestSupport INTERFACE)",
    "target_include_directories(PrismTestSupport INTERFACE ${PROJECT_SOURCE_DIR}/tests)",
  ].join("\n"));
  for (const [relativePath, content] of extraTestFiles) writeFile(root, relativePath, content);
  writeFile(root, "tests/Prism/CMakeLists.txt", testCMake);
  return root;
}

function createVisibilityFixture(t, { probeSource, productionCMake = "" }) {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "add_subdirectory(../TestSupport)",
    "add_executable(VisibilityConsumer VisibilityProbe.cpp)",
    "target_link_libraries(VisibilityConsumer PRIVATE Prism PrismTestSupport)",
  ].join("\n"), [["tests/Prism/VisibilityProbe.cpp", probeSource]]);
  writeFile(root, "tests/TestSupport/Prism/VisibilitySupport.hpp", [
    "#pragma once",
    "#include <Prism/Probe.hpp>",
  ].join("\n"));
  if (productionCMake) {
    fs.appendFileSync(path.join(root, "Src", "Prism", "CMakeLists.txt"), `\n${productionCMake}\n`);
  }
  return root;
}

function createPublicHeaderOwnerFixture(t, {
  headerName,
  productionCMake = "",
  testCMakeExtra = [],
  testSupportLinks = [],
  consumerCondition = "",
}) {
  const testCMake = [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "add_subdirectory(../TestSupport)",
  ];
  const consumerCommands = [
    "add_executable(VisibilityConsumer VisibilityProbe.cpp)",
    "target_link_libraries(VisibilityConsumer PRIVATE PrismTestSupport)",
    ...testCMakeExtra,
  ];
  if (consumerCondition) testCMake.push(`if(${consumerCondition})`);
  testCMake.push(...consumerCommands);
  if (consumerCondition) testCMake.push("endif()");
  const root = createFixture(t, testCMake.join("\n"), [[
    "tests/Prism/VisibilityProbe.cpp",
    [
      "#include <TestSupport/Prism/VisibilitySupport.hpp>",
      "int main() { return 0; }",
    ].join("\n"),
  ], [
    "tests/TestSupport/Prism/VisibilitySupport.hpp",
    [
      "#pragma once",
      `#include <Prism/${headerName}>`,
    ].join("\n"),
  ]]);
  const supportCMake = [
    "add_library(PrismTestSupport INTERFACE)",
    "target_include_directories(PrismTestSupport INTERFACE ${PROJECT_SOURCE_DIR}/Include ${PROJECT_SOURCE_DIR}/tests)",
  ];
  if (testSupportLinks.length > 0) {
    supportCMake.push(`target_link_libraries(PrismTestSupport INTERFACE ${testSupportLinks.join(" ")})`);
  }
  writeFile(root, "tests/TestSupport/CMakeLists.txt", supportCMake.join("\n"));
  if (productionCMake) {
    fs.appendFileSync(path.join(root, "Src", "Prism", "CMakeLists.txt"), `\n${productionCMake}\n`);
  }
  return root;
}

function runScanner(root) {
  const result = spawnSync(process.execPath, [path.join(root, "scripts", "check_prism_reachability.mjs")], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, `scanner terminated by signal ${result.signal}`);
  return { exitCode: result.status, ...JSON.parse(result.stdout) };
}

test("expands source-root prefixes and permits multiple test CPP files in one target", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "set(EXTRA_TEST_SOURCES SecondTest.cpp)",
    "list(APPEND EXTRA_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/ThirdTest.cpp)",
    "target_sources(FirstTest PRIVATE ${EXTRA_TEST_SOURCES})",
  ].join("\n"), [["tests/Prism/ThirdTest.cpp", "TEST(Probe, Third) {}\n"]]);

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.unresolvedCMakeSources, 0);
  assert.ok(result.summary.reachableTargets.includes("PrismFoundation"));
});

test("rejects one test CPP registered by multiple targets", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "target_sources(FirstTest PRIVATE SecondTest.cpp)",
  ].join("\n"));

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.duplicateTestSourceOwners, 1);
  assert.ok(result.problems.duplicateTestSourceOwners[0].includes("SecondTest.cpp"));
});

test("rejects unresolved CMake expressions in test source positions", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "target_sources(FirstTest PRIVATE ${UNKNOWN_TEST_SOURCES})",
  ].join("\n"));

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.ok(result.summary.counts.unresolvedCMakeSources > 0);
  assert.ok(result.problems.unresolvedCMakeSources.some((finding) => finding.includes("UNKNOWN_TEST_SOURCES")));
});

test("resolves source variables used by CXX translation-unit properties", (t) => {
  const root = createFixture(t, "AddPrismTest(FirstTest.cpp)\n");
  const productionCMake = path.join(root, "Src", "Prism", "CMakeLists.txt");
  fs.appendFileSync(productionCMake, [
    "set(OWNER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/Probe.cpp)",
    "set_source_files_properties(${OWNER_SOURCES} PROPERTIES LANGUAGE CXX)",
  ].join("\n"));
  writeFile(root, "tests/Prism/FirstTest.cpp", [
    '#include "../../Src/Prism/Probe.cpp"',
    "TEST(Probe, First) {}",
  ].join("\n"));

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.tuRootIncluders, 1);
  assert.ok(result.problems.tuRootIncluders[0].includes("FirstTest.cpp"));
});

test("inherits parent source variables into subdirectory CMake files", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "set(CHILD_TEST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/Child/ChildTest.cpp)",
    "add_subdirectory(Child)",
  ].join("\n"));
  writeFile(root, "tests/Prism/Child/CMakeLists.txt", "AddPrismTest(${CHILD_TEST_SOURCE})\n");
  writeFile(root, "tests/Prism/Child/ChildTest.cpp", "TEST(Probe, Child) {}\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.unresolvedCMakeSources, 0);
});

test("rejects unresolved CMake subdirectory expressions", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "add_subdirectory(${UNKNOWN_SUBDIRECTORY})",
  ].join("\n"));

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.unresolvedCMakeDirectories, 1);
  assert.ok(result.problems.unresolvedCMakeDirectories[0].includes("UNKNOWN_SUBDIRECTORY"));
});

test("rejects a source owner target that was never declared", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "target_sources(UnknownTarget PRIVATE Helper.cpp)",
  ].join("\n"), [["tests/Prism/Helper.cpp", "int Helper() { return 0; }\n"]]);

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.unknownTestSourceTargets, 1);
  assert.ok(result.problems.unknownTestSourceTargets[0].includes("UnknownTarget"));
});

test("requires the test target to own the private Src include root", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
  ].join("\n"));
  writeFile(root, "tests/Prism/FirstTest.cpp", [
    "#include <Prism/Detail/Private.hpp>",
    "TEST(Probe, First) {}",
  ].join("\n"));

  const withoutPrivateRoot = runScanner(root);
  assert.equal(withoutPrivateRoot.exitCode, 1);
  assert.equal(withoutPrivateRoot.summary.counts.danglingIncludes, 1);
  assert.ok(withoutPrivateRoot.problems.danglingIncludes.registeredTest[0].includes("Private.hpp"));

  fs.appendFileSync(path.join(root, "tests", "Prism", "CMakeLists.txt"),
    "\ntarget_include_directories(FirstTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)\n");
  const withPrivateRoot = runScanner(root);

  assert.equal(withPrivateRoot.exitCode, 0, JSON.stringify(withPrivateRoot.problems, null, 2));
});

test("rejects case-mismatched private includes on case-sensitive and insensitive filesystems", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "target_include_directories(FirstTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)",
  ].join("\n"));
  writeFile(root, "tests/Prism/FirstTest.cpp", [
    "#include <Prism/detail/private.hpp>",
    "TEST(Probe, First) {}",
  ].join("\n"));

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.ok(result.summary.counts.caseMismatch > 0 || result.summary.counts.danglingIncludes > 0);
});

test("rejects declared subdirectories that have no CMakeLists file", (t) => {
  const root = createFixture(t, "AddPrismTest(FirstTest.cpp)\nadd_subdirectory(Empty)\n");
  fs.mkdirSync(path.join(root, "tests", "Prism", "Empty"));

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.missingCMake, 1);
  assert.ok(result.problems.missingCMake[0].includes("Empty"));
});

test("inherits exported Include and TestSupport roots through target links", (t) => {
  const root = createVisibilityFixture(t, {
    probeSource: [
      "#include <Prism/Probe.hpp>",
      "#include <TestSupport/Prism/VisibilitySupport.hpp>",
      "int main() { return 0; }",
    ].join("\n"),
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingCMake, 0);
  assert.equal(result.summary.counts.danglingIncludes, 0);
});

test("requires the compiled owner of a public header included through TestSupport", (t) => {
  const root = createPublicHeaderOwnerFixture(t, { headerName: "Probe.hpp" });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
  assert.ok(result.problems.missingTestOwnerLinks[0].includes("VisibilitySupport.hpp"));
  assert.ok(result.problems.missingTestOwnerLinks[0].includes("Include/Prism/Probe.hpp"));
  assert.ok(result.problems.missingTestOwnerLinks[0].includes("VisibilityConsumer"));
  assert.ok(result.problems.missingTestOwnerLinks[0].includes("Prism [compiled]"));
  assert.equal(result.summary.testOwnerLinkCoverage.status, "complete");
  assert.equal(result.summary.testOwnerLinkCoverage.ambiguousTestSupportSkipCount, 0);
  assert.deepEqual(result.summary.conditionEvaluation, {
    supportedFalseLiterals: ["FALSE", "0", "OFF", "NO", "N", "IGNORE", "NOTFOUND", "<name>-NOTFOUND"],
    supportedTrueLiterals: ["TRUE", "1", "ON", "YES", "Y"],
    supportedUnary: "NOT <one supported literal>",
    otherExpressions: "Not evaluated; conservatively treated as potentially reachable.",
  });
});

test("reports partial public-owner coverage for ambiguous TestSupport headers", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "add_subdirectory(../TestSupport)",
    "add_executable(VisibilityConsumer VisibilityProbe.cpp)",
    "target_link_libraries(VisibilityConsumer PRIVATE PrismTestSupport)",
  ].join("\n"), [[
    "tests/Prism/VisibilityProbe.cpp",
    [
      "#include <TestSupport/Prism/VisibilitySupport.hpp>",
      "int main() { return 0; }",
    ].join("\n"),
  ], [
    "tests/TestSupport/Prism/VisibilitySupport.hpp",
    [
      "#pragma once",
      "#include <Prism/Probe.hpp>",
      "#include <Prism/Second.hpp>",
    ].join("\n"),
  ], [
    "Include/Prism/Second.hpp",
    "#pragma once\n",
  ], [
    "Src/Prism/OwnerB.cpp",
    "int OwnerB() { return 0; }\n",
  ]]);
  writeFile(root, "tests/TestSupport/CMakeLists.txt", [
    "add_library(PrismTestSupport INTERFACE)",
    "target_include_directories(PrismTestSupport INTERFACE ${PROJECT_SOURCE_DIR}/Include ${PROJECT_SOURCE_DIR}/tests)",
  ].join("\n"));
  fs.appendFileSync(path.join(root, "Src", "Prism", "CMakeLists.txt"), [
    "",
    "add_library(PrismOwnerB STATIC OwnerB.cpp)",
    "target_sources(PrismOwnerB PUBLIC ${PROJECT_SOURCE_DIR}/Include/Prism/Second.hpp)",
    "target_link_libraries(Prism PUBLIC PrismOwnerB)",
  ].join("\n"));

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
  assert.equal(result.summary.testOwnerLinkCoverage.status, "partial");
  assert.equal(result.summary.testOwnerLinkCoverage.ambiguousTestSupportSkipCount, 1);
  assert.deepEqual(result.summary.testOwnerLinkCoverage.ambiguousTestSupportSkips, [{
    header: "tests/TestSupport/Prism/VisibilitySupport.hpp",
    consumerTarget: "VisibilityConsumer",
    owners: ["Prism", "PrismOwnerB"],
    publicHeaders: ["Include/Prism/Probe.hpp", "Include/Prism/Second.hpp"],
  }]);
});

test("follows a compiled public header owner through a static target's private link", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "add_library(ProbeFacade STATIC Facade.cpp)",
      "target_link_libraries(ProbeFacade PRIVATE Prism)",
      "target_link_libraries(VisibilityConsumer PRIVATE ProbeFacade)",
    ],
  });
  writeFile(root, "tests/Prism/Facade.cpp", "int Facade() { return 0; }\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("does not propagate a shared target's private owner link to its consumer", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "add_library(SharedFacade SHARED SharedFacade.cpp)",
      "target_link_libraries(SharedFacade PRIVATE Prism)",
      "target_link_libraries(VisibilityConsumer PRIVATE SharedFacade)",
    ],
  });
  writeFile(root, "tests/Prism/SharedFacade.cpp", "int SharedFacade() { return 0; }\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
});

test("follows an explicit LINK_ONLY dependency from a static target", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "add_library(ProbeFacade STATIC Facade.cpp)",
      'target_link_libraries(ProbeFacade INTERFACE "$<LINK_ONLY:Prism>")',
      "target_link_libraries(VisibilityConsumer PRIVATE ProbeFacade)",
    ],
  });
  writeFile(root, "tests/Prism/Facade.cpp", "int Facade() { return 0; }\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("does not propagate a legacy LINK_PRIVATE owner dependency", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "add_library(LegacyFacade STATIC LegacyFacade.cpp)",
      "target_link_libraries(LegacyFacade LINK_PRIVATE Prism)",
      "target_link_libraries(VisibilityConsumer PRIVATE LegacyFacade)",
    ],
  });
  writeFile(root, "tests/Prism/LegacyFacade.cpp", "int LegacyFacade() { return 0; }\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
});

test("follows a compiled public header owner through a static target's public link", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "add_library(ProbeFacade STATIC Facade.cpp)",
      "target_link_libraries(ProbeFacade PUBLIC Prism)",
      "target_link_libraries(VisibilityConsumer PRIVATE ProbeFacade)",
    ],
  });
  writeFile(root, "tests/Prism/Facade.cpp", "int Facade() { return 0; }\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("follows a compiled public header owner through a static target cycle", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "add_library(ProbeCycleA STATIC CycleA.cpp)",
      "add_library(ProbeCycleB STATIC CycleB.cpp)",
      "target_link_libraries(ProbeCycleA PUBLIC ProbeCycleB)",
      "target_link_libraries(ProbeCycleB PUBLIC ProbeCycleA Prism)",
      "target_link_libraries(VisibilityConsumer PRIVATE ProbeCycleA)",
    ],
  });
  writeFile(root, "tests/Prism/CycleA.cpp", "int CycleA() { return 0; }\n");
  writeFile(root, "tests/Prism/CycleB.cpp", "int CycleB() { return 0; }\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("follows a compiled public header owner through TestSupport's interface link", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testSupportLinks: ["Prism"],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("follows an alias target to the compiled public header owner", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "add_library(PrismOwnerAlias ALIAS Prism)",
      "target_link_libraries(VisibilityConsumer PRIVATE PrismOwnerAlias)",
    ],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("inherits public include roots through a linked alias target", (t) => {
  const root = createFixture(t, [
    "AddPrismTest(FirstTest.cpp)",
    "AddPrismTest(SecondTest.cpp)",
    "add_executable(VisibilityConsumer VisibilityProbe.cpp)",
    "add_library(PrismOwnerAlias ALIAS Prism)",
    "target_link_libraries(VisibilityConsumer PRIVATE PrismOwnerAlias)",
  ].join("\n"), [[
    "tests/Prism/VisibilityProbe.cpp",
    [
      "#include <Prism/Probe.hpp>",
      "int main() { return 0; }",
    ].join("\n"),
  ]]);

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("requires every direct owner registered with target_sources", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "MultiOwner.hpp",
    productionCMake: [
      "add_library(ProbeOwnerA STATIC ProbeOwnerA.cpp)",
      "target_sources(ProbeOwnerA PUBLIC ${PROJECT_SOURCE_DIR}/Include/Prism/MultiOwner.hpp)",
      "add_library(ProbeOwnerB INTERFACE)",
      "target_sources(ProbeOwnerB INTERFACE ${PROJECT_SOURCE_DIR}/Include/Prism/MultiOwner.hpp)",
      "target_link_libraries(Prism PUBLIC ProbeOwnerA ProbeOwnerB)",
    ].join("\n"),
  });
  writeFile(root, "Src/Prism/ProbeOwnerA.cpp", "int ProbeOwnerA() { return 0; }\n");
  writeFile(root, "Include/Prism/MultiOwner.hpp", "#pragma once\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 2);
  assert.ok(result.problems.missingTestOwnerLinks.some((finding) => finding.includes("ProbeOwnerA [compiled]")));
  assert.ok(result.problems.missingTestOwnerLinks.some((finding) => finding.includes("ProbeOwnerB [INTERFACE]")));
});

test("rejects a link name that is not a declared public header owner target", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "UnknownOwner.hpp",
    productionCMake: [
      "target_sources(PrismMissingOwner PUBLIC ${PROJECT_SOURCE_DIR}/Include/Prism/UnknownOwner.hpp)",
      "target_link_libraries(Prism PUBLIC PrismMissingOwner)",
    ].join("\n"),
    testCMakeExtra: ["target_link_libraries(VisibilityConsumer PRIVATE PrismMissingOwner)"],
  });
  writeFile(root, "Include/Prism/UnknownOwner.hpp", "#pragma once\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
  assert.ok(result.problems.missingTestOwnerLinks[0].includes("not a declared production target"));
});

test("does not treat an uncalled CMake function or macro body as a test link", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "function(AddDormantFunctionLinks)",
      "target_link_libraries(VisibilityConsumer PRIVATE Prism)",
      "endfunction()",
      "macro(AddDormantMacroLinks)",
      "target_link_libraries(VisibilityConsumer PRIVATE Prism)",
      "endmacro()",
    ],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
  assert.ok(result.problems.missingTestOwnerLinks[0].includes("VisibilityConsumer"));
});

test("does not treat command-like text inside a CMake string as a test link", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      'set(DormantCommandText "target_link_libraries(VisibilityConsumer PRIVATE Prism)")',
      "set(DormantBracketText [=[target_link_libraries(VisibilityConsumer PRIVATE Prism)]=])",
    ],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
});

test("does not treat possibly empty CMake loop bodies as test links", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "set(EmptyTargets)",
      "foreach(Target IN LISTS EmptyTargets)",
      "target_link_libraries(VisibilityConsumer PRIVATE Prism)",
      "endforeach()",
      "while(FALSE)",
      "target_link_libraries(VisibilityConsumer PRIVATE Prism)",
      "endwhile()",
    ],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
});

test("does not accept an owner link that exists only in a false CMake branch", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      "if(FALSE)",
      "target_link_libraries(VisibilityConsumer PRIVATE Prism)",
      "endif()",
    ],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
});

test("does not treat a debug-only owner link as valid for every configuration", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: ["target_link_libraries(VisibilityConsumer PRIVATE debug Prism)"],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
});

test("keeps a GENERAL owner link available in every configuration", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: ["target_link_libraries(VisibilityConsumer PRIVATE general Prism)"],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("accepts an owner link in the same condition that declares its test target", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    consumerCondition: "OWNER_TESTS_ENABLED",
    testCMakeExtra: ["target_link_libraries(VisibilityConsumer PRIVATE Prism)"],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
});

test("does not accept an owner link for a test target in a literal false branch", (t) => {
  const conditions = ["FALSE", "0", "OFF", "NO", "N", "IGNORE", "Prism-NOTFOUND", "NOT TRUE"];
  for (const condition of conditions) {
    const root = createPublicHeaderOwnerFixture(t, {
      headerName: "Probe.hpp",
      consumerCondition: condition,
      testCMakeExtra: ["target_link_libraries(VisibilityConsumer PRIVATE Prism)"],
    });

    const result = runScanner(root);

    assert.equal(result.exitCode, 1, condition);
    assert.equal(result.summary.counts.danglingIncludes, 0, condition);
    assert.equal(result.summary.counts.missingTestOwnerLinks, 1, condition);
  }
});

test("does not treat a configuration-gated link expression as unconditional", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "Probe.hpp",
    testCMakeExtra: [
      'target_link_libraries(VisibilityConsumer PRIVATE "$<$<CONFIG:Debug>:Prism>")',
    ],
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.danglingIncludes, 0);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
});

test("requires a pure interface public header owner in the consumer link closure", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "HeaderOnly.hpp",
    productionCMake: [
      "PrismAddInterfaceTarget(PrismHeaderOnly HEADERS ${PROJECT_SOURCE_DIR}/Include/Prism/HeaderOnly.hpp)",
      "target_link_libraries(Prism PUBLIC PrismHeaderOnly)",
    ].join("\n"),
  });
  writeFile(root, "Include/Prism/HeaderOnly.hpp", "#pragma once\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.missingTestOwnerLinks, 1);
  assert.ok(result.problems.missingTestOwnerLinks[0].includes("PrismHeaderOnly [INTERFACE]"));
  assert.equal(result.summary.counts.danglingIncludes, 0);
});

test("accepts a pure interface public header owner without a compiled library", (t) => {
  const root = createPublicHeaderOwnerFixture(t, {
    headerName: "HeaderOnly.hpp",
    productionCMake: [
      "PrismAddInterfaceTarget(PrismHeaderOnly HEADERS ${PROJECT_SOURCE_DIR}/Include/Prism/HeaderOnly.hpp)",
      "target_link_libraries(Prism PUBLIC PrismHeaderOnly)",
    ].join("\n"),
    testSupportLinks: ["PrismHeaderOnly"],
  });
  writeFile(root, "Include/Prism/HeaderOnly.hpp", "#pragma once\n");

  const result = runScanner(root);

  assert.equal(result.exitCode, 0, JSON.stringify(result.problems, null, 2));
  assert.equal(result.summary.counts.missingTestOwnerLinks, 0);
  assert.equal(result.summary.counts.danglingIncludes, 0);
});

test("does not propagate a dependency's PRIVATE Src root to its consumer", (t) => {
  const root = createVisibilityFixture(t, {
    probeSource: [
      "#include <Prism/Probe.hpp>",
      "#include <Prism/Detail/Private.hpp>",
      "int main() { return 0; }",
    ].join("\n"),
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.privateSourceIncludes, 1);
  assert.equal(result.summary.counts.danglingIncludes, 1);
  assert.ok(result.problems.danglingIncludes.registeredTest.some((finding) =>
    finding.includes("VisibilityProbe.cpp -> Prism/Detail/Private.hpp")));
});

test("rejects PUBLIC and INTERFACE exports of the Src include root", (t) => {
  const publicRoot = createVisibilityFixture(t, {
    probeSource: "int main() { return 0; }\n",
    productionCMake: 'target_include_directories(Prism PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Src>")',
  });
  const publicResult = runScanner(publicRoot);

  assert.equal(publicResult.exitCode, 1);
  assert.equal(publicResult.summary.counts.publicSourceIncludeDirectories, 1);
  assert.ok(publicResult.problems.publicSourceIncludeDirectories.some((finding) => finding.startsWith("Prism ")));

  const interfaceRoot = createVisibilityFixture(t, {
    probeSource: "int main() { return 0; }\n",
    productionCMake: [
      "add_library(SrcExporter INTERFACE)",
      'target_include_directories(SrcExporter INTERFACE "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Src>")',
    ].join("\n"),
  });
  const interfaceResult = runScanner(interfaceRoot);

  assert.equal(interfaceResult.exitCode, 1);
  assert.equal(interfaceResult.summary.counts.publicSourceIncludeDirectories, 1);
  assert.ok(interfaceResult.problems.publicSourceIncludeDirectories.some((finding) => finding.startsWith("SrcExporter ")));
});

test("reports a case mismatch for a lowercase project include prefix", (t) => {
  const root = createVisibilityFixture(t, {
    probeSource: [
      "#include <prism/Probe.hpp>",
      "int main() { return 0; }",
    ].join("\n"),
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.ok(result.summary.counts.caseMismatch > 0);
  assert.ok(result.problems.caseMismatch.some((finding) =>
    finding.includes("VisibilityProbe.cpp -> prism/Probe.hpp")));
});

test("rejects unresolved include directory generator expressions", (t) => {
  const root = createVisibilityFixture(t, {
    probeSource: "int main() { return 0; }\n",
    productionCMake: 'target_include_directories(Prism PUBLIC "$<UNKNOWN_INTERFACE:${PROJECT_SOURCE_DIR}/Include>")',
  });

  const result = runScanner(root);

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.counts.unresolvedCMakeDirectories, 1);
  assert.ok(result.problems.unresolvedCMakeDirectories[0].includes("UNKNOWN_INTERFACE"));
});
