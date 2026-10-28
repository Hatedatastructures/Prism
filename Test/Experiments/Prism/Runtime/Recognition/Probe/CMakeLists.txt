# Probe 防御实验测试。
AddExperimentTest(DefenseCoverage.cpp ProbeDefenseCoverage)
target_link_libraries(ExperimentProbeDefenseCoverage PRIVATE
    ExperimentalProbeDefenseSupport PrismRuntime)
