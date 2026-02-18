// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";
import {MockCoinbaseSmartWallet} from "../../lib/mocks/MockCoinbaseSmartWallet.sol";
import {RecordingReplacePolicy} from "../../lib/testPolicies/RecordingReplacePolicy.sol";
import {RevertOnReplacePolicy} from "../../lib/testPolicies/RevertOnReplacePolicy.sol";
import {RevertOnUninstallForReplacePolicy} from "../../lib/testPolicies/RevertOnUninstallForReplacePolicy.sol";

/// @title ReplaceTest
///
/// @notice Test contract for `PolicyManager.replace`.
contract ReplaceTest is PolicyManagerTestBase {
    /// @dev Base timestamp used when warping for validity-window tests.
    uint256 internal constant WARP_BASE_TIMESTAMP = 1_000_000;
    /// @dev Config seed used for the new policy binding when a single canonical config is needed.
    uint256 internal constant DEFAULT_NEW_CONFIG_SEED = 1;
    /// @dev Salt used for the new policy binding when a single canonical salt is needed.
    uint256 internal constant DEFAULT_NEW_SALT = 1;
    /// @dev Salt used for the old policy binding when a single canonical salt is needed.
    uint256 internal constant DEFAULT_OLD_SALT = 0;

    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Installs `callPolicy` for `account` using the given config + binding parameters.
    ///
    /// @param installPolicyConfig Policy config bytes used for installation (hashed into the binding).
    /// @param salt Salt used to derive a distinct `policyId`.
    /// @param validAfter Lower-bound timestamp (seconds) for the binding.
    /// @param validUntil Upper-bound timestamp (seconds) for the binding.
    ///
    /// @return policyId Deterministic binding identifier derived from the provided binding inputs.
    /// @return policyConfig The same config bytes passed to install (returned for convenience).
    function _installCallPolicy(bytes memory installPolicyConfig, uint256 salt, uint40 validAfter, uint40 validUntil)
        internal
        returns (bytes32 policyId, bytes memory policyConfig)
    {
        policyConfig = installPolicyConfig;
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            validAfter: validAfter,
            validUntil: validUntil,
            salt: salt,
            policyConfig: policyConfig
        });

        vm.prank(address(account));
        policyId = policyManager.install(binding);
    }

    /// @notice Performs a replacement via direct account call.
    ///
    /// @param oldPolicy Old policy contract address.
    /// @param oldPolicyId Old policy identifier.
    /// @param oldPolicyConfig Old policy config bytes.
    /// @param newBinding New policy binding (carries its own policyConfig).
    ///
    /// @return newPolicyId Deterministic policy identifier for the new binding.
    function _replaceViaAccount(
        address oldPolicy,
        bytes32 oldPolicyId,
        bytes memory oldPolicyConfig,
        PolicyManager.PolicyBinding memory newBinding
    ) internal returns (bytes32 newPolicyId) {
        PolicyManager.ReplacePayload memory payload =
            PolicyManager.ReplacePayload({
                oldPolicy: oldPolicy, oldPolicyId: oldPolicyId, oldPolicyConfig: oldPolicyConfig, newBinding: newBinding
            });
        vm.prank(newBinding.account);
        return policyManager.replace(payload);
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller is not `payload.newBinding.account`.
    ///
    /// @dev Expects `PolicyManager.InvalidSender`.
    ///
    /// @param caller Non-account caller (fuzzed).
    function test_reverts_whenCallerNotAccount(address caller) public {
        vm.assume(caller != address(0));
        vm.assume(caller != address(account));

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidSender.selector, caller, address(account)));
        vm.prank(caller);
        policyManager.replace(payload);
    }

    /// @notice Reverts when `oldPolicy` or `newBinding.policy` is zero.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenOldPolicyIsZeroAddress() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(0), oldPolicyId: oldPolicyId, oldPolicyConfig: oldPolicyConfig, newBinding: newBinding
        });
        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when `newBinding.policy` is the zero address.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenNewPolicyIsZeroAddress() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        newBinding.policy = address(0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });
        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when `newPolicyId == oldPolicyId`.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenNewPolicyIdEqualsOldPolicyId() public {
        bytes memory config = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), config, DEFAULT_OLD_SALT);
        vm.prank(address(account));
        bytes32 policyId = policyManager.install(binding);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy), oldPolicyId: policyId, oldPolicyConfig: config, newBinding: binding
        });

        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when the old policyId is not installed.
    ///
    /// @dev Expects `PolicyManager.PolicyNotInstalled`. Derives an uninstalled policyId from a different
    ///      (configSeed, salt) than the installed one to avoid discarding fuzz cases.
    ///
    /// @param configSeedInstalled Seed used to build the installed policy config (hashed into `policyId`).
    /// @param saltInstalled Salt used for the installed binding (hashed into `policyId`).
    /// @param offsetSeed Seed used to derive a distinct (configSeed, salt) for the uninstalled policyId.
    function test_reverts_whenOldPolicyNotInstalled(
        bytes32 configSeedInstalled,
        uint256 saltInstalled,
        uint256 offsetSeed
    ) public {
        saltInstalled = bound(saltInstalled, 0, type(uint256).max - 1);
        offsetSeed = bound(offsetSeed, 0, type(uint256).max - 1);
        _installCallPolicy(abi.encode(configSeedInstalled), saltInstalled, 0, 0);

        uint256 saltUninstalled = saltInstalled + 1;
        bytes32 configSeedUninstalled = bytes32(uint256(configSeedInstalled) ^ (1 + offsetSeed));
        PolicyManager.PolicyBinding memory uninstalledBinding =
            _binding(address(callPolicy), abi.encode(configSeedUninstalled), saltUninstalled);
        bytes32 oldPolicyId = policyManager.getPolicyId(uninstalledBinding);

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy), oldPolicyId: oldPolicyId, oldPolicyConfig: "", newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyNotInstalled.selector, oldPolicyId));
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when the old policyId is already uninstalled.
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenOldPolicyIsDisabled() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.UninstallPayload memory uninstallPayload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), validAfter: 0, validUntil: 0, salt: 0, policyConfig: bytes("")
            }),
            policy: address(callPolicy),
            policyId: oldPolicyId,
            policyConfig: oldPolicyConfig,
            uninstallData: ""
        });
        vm.prank(address(account));
        policyManager.uninstall(uninstallPayload);

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy), oldPolicyId: oldPolicyId, oldPolicyConfig: "", newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, oldPolicyId));
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when the old policy instance is installed for a different account than `newBinding.account`.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload` (unless end state already reached and returns early).
    function test_reverts_whenOldPolicyAccountMismatch_andOldPolicyStillInstalled() public {
        MockCoinbaseSmartWallet otherAccount = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        otherAccount.initialize(owners);
        vm.prank(owner);
        otherAccount.addOwnerAddress(address(policyManager));

        PolicyManager.PolicyBinding memory oldBinding = PolicyManager.PolicyBinding({
            account: address(otherAccount),
            policy: address(callPolicy),
            validAfter: 0,
            validUntil: 0,
            salt: DEFAULT_OLD_SALT,
            policyConfig: abi.encode(bytes32(0))
        });
        vm.prank(address(otherAccount));
        bytes32 oldPolicyId = policyManager.install(oldBinding);

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        newBinding.account = address(account);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: abi.encode(bytes32(0)),
            newBinding: newBinding
        });

        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when the new policyId is already installed but the old policy is not yet uninstalled.
    ///
    /// @dev Expects `PolicyManager.PolicyAlreadyInstalled` (unless end state already reached and returns early).
    function test_reverts_whenNewPolicyAlreadyInstalled_andOldPolicyNotYetUninstalled() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        vm.prank(address(account));
        policyManager.install(newBinding);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.PolicyAlreadyInstalled.selector, policyManager.getPolicyId(newBinding))
        );
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when current timestamp is before `newBinding.validAfter`.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter`.
    ///
    /// @param validAfterSeed Seed used to pick a validAfter strictly after current timestamp.
    function test_reverts_whenNewBindingBeforeValidAfter(uint40 validAfterSeed) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint256 nowTs = block.timestamp;

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        bytes memory newConfig = abi.encode(DEFAULT_NEW_CONFIG_SEED);

        uint40 validAfter = uint40(bound(uint256(validAfterSeed), nowTs + 1, uint256(type(uint40).max)));
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            validAfter: validAfter,
            validUntil: 0,
            salt: DEFAULT_NEW_SALT,
            policyConfig: newConfig
        });
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.BeforeValidAfter.selector, uint40(nowTs), validAfter));
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when current timestamp is at/after `newBinding.validUntil`.
    ///
    /// @dev Expects `PolicyManager.AfterValidUntil`.
    ///
    /// @param validUntilSeed Seed used to pick a non-zero validUntil.
    function test_reverts_whenNewBindingAfterValidUntil(uint40 validUntilSeed) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint40 nowTs = uint40(block.timestamp);

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        bytes memory newConfig = abi.encode(DEFAULT_NEW_CONFIG_SEED);

        uint40 validUntil = uint40(bound(uint256(validUntilSeed), 1, uint256(nowTs)));
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            validAfter: 0,
            validUntil: validUntil,
            salt: DEFAULT_NEW_SALT + 1,
            policyConfig: newConfig
        });

        vm.warp(uint256(validUntil));
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.AfterValidUntil.selector, validUntil, validUntil));
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Bubbles a revert when the new policy's replacement install hook reverts.
    function test_reverts_whenNewPolicyOnReplaceReverts() public {
        RevertOnReplacePolicy revertPolicy = new RevertOnReplacePolicy(address(policyManager));

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        bytes memory newConfig = abi.encode(uint256(2));
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(revertPolicy),
            validAfter: 0,
            validUntil: 0,
            salt: DEFAULT_NEW_SALT,
            policyConfig: newConfig
        });
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectRevert(RevertOnReplacePolicy.OnReplaceReverted.selector);
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyUninstalled` for the old policy instance.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_emitsPolicyUninstalled_forOldPolicy(bytes32 configSeed, uint256 salt) public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyUninstalled(oldPolicyId, address(account), address(callPolicy));
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Emits `PolicyInstalled` for the new policy instance.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_emitsPolicyInstalled_forNewPolicy(bytes32 configSeed, uint256 salt) public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyInstalled(policyManager.getPolicyId(newBinding), address(account), address(callPolicy));
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Emits `PolicyReplaced` on successful replacement.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_emitsPolicyReplaced(bytes32 configSeed, uint256 salt) public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyReplaced(
            oldPolicyId, newPolicyId, address(account), address(callPolicy), address(callPolicy)
        );
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Calls `onReplace(..., role=OldPolicy)` for the old policy instance.
    function test_callsOnReplace_forOldPolicy() public {
        RecordingReplacePolicy oldPolicy = new RecordingReplacePolicy(address(policyManager));

        bytes memory oldConfig = abi.encode(bytes32("old"));
        PolicyManager.PolicyBinding memory oldBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(oldPolicy),
            validAfter: 0,
            validUntil: 0,
            salt: DEFAULT_OLD_SALT,
            policyConfig: oldConfig
        });
        vm.prank(address(account));
        bytes32 oldPolicyId = policyManager.install(oldBinding);

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(oldPolicy), oldPolicyId: oldPolicyId, oldPolicyConfig: oldConfig, newBinding: newBinding
        });

        vm.prank(address(account));
        policyManager.replace(payload);

        assertTrue(oldPolicy.oldPolicyCalled());
    }

    /// @notice Calls `onReplace(..., role=NewPolicy)` for the new policy instance.
    function test_callsOnReplace_forNewPolicy() public {
        RecordingReplacePolicy newPolicy = new RecordingReplacePolicy(address(policyManager));

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        bytes memory newConfig = abi.encode(uint256(2));
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(newPolicy),
            validAfter: 0,
            validUntil: 0,
            salt: DEFAULT_NEW_SALT,
            policyConfig: newConfig
        });
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.prank(address(account));
        policyManager.replace(payload);

        assertTrue(newPolicy.newPolicyCalled());
    }

    /// @notice Old policy uninstall hook revert cannot block replacement when effective caller is the account.
    function test_oldPolicyHookRevert_doesNotBlockReplace() public {
        RevertOnUninstallForReplacePolicy oldPolicy = new RevertOnUninstallForReplacePolicy(address(policyManager));

        bytes memory oldConfig = abi.encode(bytes32("old"));
        PolicyManager.PolicyBinding memory oldBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(oldPolicy),
            validAfter: 0,
            validUntil: 0,
            salt: DEFAULT_OLD_SALT,
            policyConfig: oldConfig
        });
        vm.prank(address(account));
        bytes32 oldPolicyId = policyManager.install(oldBinding);

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(oldPolicy), oldPolicyId: oldPolicyId, oldPolicyConfig: oldConfig, newBinding: newBinding
        });

        vm.prank(address(account));
        policyManager.replace(payload);

        assertTrue(policyManager.isPolicyActive(address(callPolicy), newPolicyId));
    }

    // =============================================================
    // Edge cases
    // =============================================================

    /// @notice If the desired end state is already reached, replacement returns early (idempotent).
    function test_isIdempotent_whenEndStateAlreadyReached_returnsEarly() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);

        _replaceViaAccount(address(callPolicy), oldPolicyId, oldPolicyConfig, newBinding);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            newBinding: newBinding
        });

        vm.recordLogs();
        vm.prank(address(account));
        bytes32 ret = policyManager.replace(payload);
        assertEq(ret, policyManager.getPolicyId(newBinding));
        assertEq(vm.getRecordedLogs().length, 0);
    }
}
