// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";
import {InstallTestPolicy} from "../../lib/testPolicies/InstallTestPolicy.sol";

/// @title InstallTest
///
/// @notice Test contract for `PolicyManager.install`.
contract InstallTest is PolicyManagerTestBase {
    /// @dev Maximum length for fuzzed `bytes` inputs to keep fuzz runs fast.
    uint256 internal constant MAX_BYTES_LEN = 256;
    /// @dev Base timestamp used for warp-based tests (replaces magic values).
    uint40 internal constant WARP_BASE_TIMESTAMP = 1_000_000;

    InstallTestPolicy internal installPolicy;

    function setUp() public {
        setUpPolicyManagerBase();
        installPolicy = new InstallTestPolicy(address(policyManager));
        vm.label(address(installPolicy), "InstallTestPolicy");
    }

    /// @notice Installs a policy using the given binding and config.
    ///
    /// @param binding Policy binding parameters.
    /// @param policyConfig Config bytes whose hash must match `binding.policyConfigHash`.
    /// @return policyId The installed policy identifier.
    function _install(PolicyManager.PolicyBinding memory binding, bytes memory policyConfig)
        internal
        returns (bytes32 policyId)
    {
        vm.prank(binding.account);
        return policyManager.install(binding, policyConfig);
    }

    /// @notice Returns a config seed that does not trigger InstallTestPolicy's revert sentinel.
    function _safeConfigSeed(bytes32 configSeed) internal pure returns (bytes32) {
        bytes32 mask = bytes32(uint256(0xff) << 248);
        if ((configSeed & mask) == mask) {
            return configSeed ^ mask;
        }
        return configSeed;
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller is not `binding.account`.
    ///
    /// @dev Expects `PolicyManager.InvalidSender`.
    ///
    /// @param caller Non-account caller (fuzzed).
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenCallerNotAccount(address caller, bytes32 configSeed, uint256 salt) public {
        caller = caller == address(account) ? address(1) : caller;

        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidSender.selector, caller, address(account)));
        vm.prank(caller);
        policyManager.install(binding, policyConfig);
    }

    /// @notice Reverts when the policyId has been uninstalled (prevents future installs).
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenPolicyIsDisabled(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        bytes32 policyId = _install(binding, policyConfig);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(installPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });
        vm.prank(address(account));
        policyManager.uninstall(payload);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, policyId));
        _install(binding, policyConfig);
    }

    /// @notice Reverts when `policyConfig` hash does not match `binding.policyConfigHash`.
    ///
    /// @dev Expects `PolicyManager.PolicyConfigHashMismatch`.
    ///
    /// @param committedConfigSeed Seed used to build the committed config bytes.
    /// @param mismatchedConfigSeed Seed used to build the mismatched config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenPolicyConfigHashMismatch(
        bytes32 committedConfigSeed,
        bytes32 mismatchedConfigSeed,
        uint256 salt
    ) public {
        bytes memory committedConfig = abi.encode(_safeConfigSeed(committedConfigSeed));
        bytes memory policyConfig = abi.encode(_safeConfigSeed(mismatchedConfigSeed));
        if (keccak256(policyConfig) == keccak256(committedConfig)) {
            policyConfig[0] = bytes1(uint8(policyConfig[0]) ^ 0x01);
        }

        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), committedConfig, salt);

        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyManager.PolicyConfigHashMismatch.selector, keccak256(policyConfig), binding.policyConfigHash
            )
        );
        _install(binding, policyConfig);
    }

    /// @notice Reverts when current timestamp is before `binding.validAfter`.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter`.
    ///
    /// @param validAfterSeed Seed used to derive a future validAfter bound.
    /// @param beforeOffset Seed used to pick a timestamp strictly before validAfter.
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenBeforeValidAfter(
        uint40 validAfterSeed,
        uint40 beforeOffset,
        bytes32 configSeed,
        uint256 salt
    ) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint40 nowTs = uint40(block.timestamp);
        uint40 validAfter = uint40(bound(uint256(validAfterSeed), uint256(nowTs) + 1, uint256(type(uint40).max)));

        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        binding.validAfter = validAfter;
        binding.validUntil = 0;

        uint40 range = validAfter;
        uint40 beforeTs = uint40(uint256(beforeOffset) % uint256(range));
        vm.warp(uint256(beforeTs));

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.BeforeValidAfter.selector, beforeTs, validAfter));
        _install(binding, policyConfig);
    }

    /// @notice Reverts when current timestamp is at/after `binding.validUntil`.
    ///
    /// @dev Expects `PolicyManager.AfterValidUntil`.
    ///
    /// @param validUntilSeed Seed used to derive a past validUntil bound.
    /// @param afterOffset Seed used to pick a timestamp at/after validUntil.
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenAfterValidUntil(
        uint40 validUntilSeed,
        uint40 afterOffset,
        bytes32 configSeed,
        uint256 salt
    ) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint40 nowTs = uint40(block.timestamp);
        uint40 validUntil = uint40(bound(uint256(validUntilSeed), 1, uint256(nowTs)));

        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        binding.validAfter = 0;
        binding.validUntil = validUntil;

        uint40 range = type(uint40).max - validUntil + 1;
        uint40 atOrAfter = validUntil + uint40(uint256(afterOffset) % uint256(range));
        vm.warp(uint256(atOrAfter));

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.AfterValidUntil.selector, atOrAfter, validUntil));
        _install(binding, policyConfig);
    }

    /// @notice Bubbles a revert when the policy's `onInstall` hook reverts.
    ///
    /// @dev Expects the policy-defined revert to bubble from `Policy(policy).onInstall(...)`.
    ///
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenPolicyOnInstallReverts(uint256 salt) public {
        bytes memory policyConfig = hex"ff";
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        vm.expectRevert(InstallTestPolicy.OnInstallReverted.selector);
        _install(binding, policyConfig);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyInstalled` on first install.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_emitsPolicyInstalled(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        bytes32 policyId = policyManager.getPolicyId(binding);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyInstalled(policyId, address(account), address(installPolicy));
        _install(binding, policyConfig);
    }

    /// @notice Installs a policy instance and writes a lifecycle record.
    ///
    /// @dev Verifies that `policies(policy, policyId)` reflects binding fields.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_installs_andStoresRecord(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        bytes32 policyId = _install(binding, policyConfig);

        (bool installed, bool uninstalled, address recordAccount, uint40 validAfter, uint40 validUntil) =
            policyManager.policies(address(installPolicy), policyId);

        assertTrue(installed);
        assertFalse(uninstalled);
        assertEq(recordAccount, address(account));
        assertEq(validAfter, binding.validAfter);
        assertEq(validUntil, binding.validUntil);
    }

    /// @notice Calls the policy hook with the account as effective caller.
    ///
    /// @dev Verifies `policy.onInstall(..., effectiveCaller)` receives `binding.account` as `effectiveCaller`.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_callsOnInstall_withAccountAsCaller(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        _install(binding, policyConfig);

        assertEq(installPolicy.lastEffectiveCaller(), address(account));
        assertEq(installPolicy.lastAccount(), address(account));
    }

    /// @notice Allows installing multiple otherwise identical bindings via distinct salts.
    ///
    /// @dev Same (account, policy, configHash) but different salts => different policyIds => both installable.
    function test_allowsMultipleInstalls_withDifferentSalts(uint256 saltA, uint256 saltB) public {
        uint256 saltBAdjusted = saltA == saltB ? saltA + 1 : saltB;

        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory bindingA = _binding(address(installPolicy), policyConfig, saltA);
        PolicyManager.PolicyBinding memory bindingB = _binding(address(installPolicy), policyConfig, saltBAdjusted);

        bytes32 policyIdA = _install(bindingA, policyConfig);
        bytes32 policyIdB = _install(bindingB, policyConfig);

        assertTrue(policyIdA != policyIdB);
        (bool installedA,,,,) = policyManager.policies(address(installPolicy), policyIdA);
        (bool installedB,,,,) = policyManager.policies(address(installPolicy), policyIdB);
        assertTrue(installedA);
        assertTrue(installedB);
    }

    /// @notice Stores `validAfter`/`validUntil` from the binding into the policy record.
    ///
    /// @param validAfter Lower-bound timestamp (seconds).
    /// @param validUntil Upper-bound timestamp (seconds).
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_storesValidityWindow_fieldsInRecord(
        uint40 validAfter,
        uint40 validUntil,
        bytes32 configSeed,
        uint256 salt
    ) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        // Ensure window ordering (or no upper bound).
        if (validUntil != 0 && validUntil <= validAfter) {
            validUntil = validAfter == type(uint40).max ? 0 : validAfter + 1;
        }
        binding.validAfter = validAfter;
        binding.validUntil = validUntil;

        // Install must occur within the binding window (PolicyManager checks the window at install time).
        if (validUntil == 0) {
            uint40 installTs = validAfter;
            if (installTs < WARP_BASE_TIMESTAMP) installTs = WARP_BASE_TIMESTAMP;
            vm.warp(uint256(installTs));
        } else {
            // Pick a timestamp in [validAfter, validUntil - 1] without discarding fuzz cases.
            uint40 range = validUntil - validAfter;
            uint40 installTs = validAfter + uint40(uint256(salt) % uint256(range));
            vm.warp(uint256(installTs));
        }

        bytes32 policyId = _install(binding, policyConfig);
        (,,, uint40 recordValidAfter, uint40 recordValidUntil) =
            policyManager.policies(address(installPolicy), policyId);
        assertEq(recordValidAfter, validAfter);
        assertEq(recordValidUntil, validUntil);
    }

    // =============================================================
    // Edge cases
    // =============================================================

    /// @notice Installing an already-installed policyId is a no-op (idempotent).
    ///
    /// @dev Second install returns the same policyId and does not call hooks or emit `PolicyInstalled`.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_isIdempotent_noHookNoEventOnSecondInstall(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        bytes32 policyId = _install(binding, policyConfig);

        vm.recordLogs();
        bytes32 policyId2 = _install(binding, policyConfig);
        assertEq(policyId2, policyId);
        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// @notice Reinstalling a previously uninstalled policyId remains blocked.
    ///
    /// @dev After uninstallation, any future install attempt for that policyId must revert `PolicyIsDisabled`.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reinstall_afterUninstall_stillBlocked(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        bytes32 policyId = _install(binding, policyConfig);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(installPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });
        vm.prank(address(account));
        policyManager.uninstall(payload);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, policyId));
        _install(binding, policyConfig);
    }

    /// @notice Empty `policyConfig` is allowed when the binding commits to its hash.
    ///
    /// @param salt Salt used to derive the policyId.
    function test_allowsEmptyPolicyConfig_whenHashMatches(uint256 salt) public {
        bytes memory policyConfig = "";
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        _install(binding, policyConfig);
    }

    /// @notice Behavior when `binding.policy` is the zero address.
    ///
    /// @dev Decide whether this should revert (preferred) or succeed as a no-op policy.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_whenPolicyIsZeroAddress_behavior(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(0), policyConfig, salt);

        vm.prank(address(account));
        vm.expectRevert();
        policyManager.install(binding, policyConfig);
    }
}

