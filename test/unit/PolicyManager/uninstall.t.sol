// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";
import {RecordAccountOnUninstallPolicy} from "../../lib/testPolicies/RecordAccountOnUninstallPolicy.sol";
import {RevertOnUninstallPolicy} from "../../lib/testPolicies/RevertOnUninstallPolicy.sol";

/// @title UninstallTest
///
/// @notice Test contract for `PolicyManager.uninstall` (both policyId-mode and binding-mode).
contract UninstallTest is PolicyManagerTestBase {
    /// @dev Maximum length for fuzzed `bytes` inputs to keep fuzz runs fast.
    uint256 internal constant MAX_BYTES_LEN = 256;

    RevertOnUninstallPolicy internal revertPolicy;
    RecordAccountOnUninstallPolicy internal recordPolicy;

    function setUp() public {
        setUpPolicyManagerBase();
        revertPolicy = new RevertOnUninstallPolicy(address(policyManager));
        recordPolicy = new RecordAccountOnUninstallPolicy(address(policyManager));
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
            policyConfigHash: keccak256(policyConfig)
        });

        vm.prank(address(account));
        policyId = policyManager.install(binding, policyConfig);
    }

    /// @notice Installs `policyContract` for `account` with the given config.
    ///
    /// @param policyContract Policy contract to install.
    /// @param installPolicyConfig Policy config bytes used for installation.
    /// @param salt Salt used to derive `policyId`.
    ///
    /// @return policyId Deterministic binding identifier.
    /// @return policyConfig The same config bytes passed to install.
    function _installPolicy(address policyContract, bytes memory installPolicyConfig, uint256 salt)
        internal
        returns (bytes32 policyId, bytes memory policyConfig)
    {
        policyConfig = installPolicyConfig;
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: policyContract,
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfigHash: keccak256(policyConfig)
        });

        vm.prank(address(account));
        policyId = policyManager.install(binding, policyConfig);
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts in policyId-mode when `policy` is zero (even if `policyId` is non-zero).
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    ///
    /// @param policyIdUint Policy identifier (as uint256). Must be non-zero.
    function test_reverts_policyIdMode_whenPolicyIsZero(uint256 policyIdUint) public {
        vm.assume(policyIdUint != 0);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(0),
            policyId: bytes32(policyIdUint),
            policyConfig: "",
            uninstallData: ""
        });

        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        policyManager.uninstall(payload);
    }

    /// @notice Reverts in policyId-mode when `policyId` is zero (even if `policy` is non-zero).
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    ///
    /// @param policy Policy address. Must be non-zero.
    function test_reverts_policyIdMode_whenPolicyIdIsZero(address policy) public {
        vm.assume(policy != address(0));

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: policy,
            policyId: bytes32(0),
            policyConfig: "",
            uninstallData: ""
        });

        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        policyManager.uninstall(payload);
    }

    /// @notice Reverts in policyId-mode when the policyId is not installed.
    ///
    /// @dev Expects `PolicyManager.PolicyNotInstalled`.
    ///
    /// @param policyIdUint Policy identifier (as uint256) that was never installed.
    function test_reverts_policyIdMode_whenPolicyNotInstalled(uint256 policyIdUint) public {
        vm.assume(policyIdUint != 0);
        bytes32 policyId = bytes32(policyIdUint);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(callPolicy),
            policyId: policyId,
            policyConfig: "",
            uninstallData: ""
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyNotInstalled.selector, policyId));
        policyManager.uninstall(payload);
    }

    /// @notice Reverts in binding-mode (pre-install) when `policyConfig` is empty.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_bindingMode_preInstall_whenPolicyConfigEmpty() public {
        bytes memory policyConfig = abi.encode(bytes32("config"));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 1);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding, policy: address(0), policyId: bytes32(0), policyConfig: "", uninstallData: ""
        });

        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        policyManager.uninstall(payload);
    }

    /// @notice Reverts in binding-mode (pre-install) when `policyConfig` hash does not match the binding commitment.
    ///
    /// @dev Expects `PolicyManager.PolicyConfigHashMismatch`.
    ///
    /// @param realConfigSeed Seed used to build the binding's committed config (hashed into policyConfigHash).
    /// @param mismatchConfigSeed Seed used to build mismatched config bytes.
    /// @param salt Salt used to build the binding.
    /// @param flipByteIndex Index of byte to flip when seeds produce matching hashes (ensures mismatch).
    function test_reverts_bindingMode_preInstall_whenPolicyConfigHashMismatch(
        bytes32 realConfigSeed,
        bytes32 mismatchConfigSeed,
        uint256 salt,
        uint256 flipByteIndex
    ) public {
        bytes memory realConfig = abi.encode(realConfigSeed);
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), realConfig, salt);

        bytes memory policyConfig = abi.encode(mismatchConfigSeed);
        if (keccak256(policyConfig) == binding.policyConfigHash) {
            policyConfig = abi.encode(mismatchConfigSeed);
            uint256 idx = flipByteIndex % policyConfig.length;
            policyConfig[idx] = bytes1(uint8(policyConfig[idx]) ^ 0x01);
        }

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding, policy: address(0), policyId: bytes32(0), policyConfig: policyConfig, uninstallData: ""
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyManager.PolicyConfigHashMismatch.selector, keccak256(policyConfig), binding.policyConfigHash
            )
        );
        policyManager.uninstall(payload);
    }

    /// @notice Reverts with `Unauthorized` when the policy uninstall hook reverts and caller is not the account.
    ///
    /// @dev Expects `PolicyManager.Unauthorized`.
    ///
    /// @param caller Caller attempting the uninstall; must not be the account.
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_reverts_whenPolicyHookReverts_andCallerNotAccount(address caller, bytes32 configSeed, uint256 salt)
        public
    {
        vm.assume(caller != address(0));
        vm.assume(caller != address(account));

        (bytes32 policyId, bytes memory policyConfig) =
            _installPolicy(address(revertPolicy), abi.encode(configSeed), salt);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(revertPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.Unauthorized.selector, caller));
        vm.prank(caller);
        policyManager.uninstall(payload);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyUninstalled` when uninstalling an installed policy instance (policyId-mode).
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_emitsPolicyUninstalled_policyIdMode_installedLifecycle(bytes32 configSeed, uint256 salt) public {
        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(callPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyUninstalled(policyId, address(account), address(callPolicy));
        vm.prank(address(account));
        policyManager.uninstall(payload);
    }

    /// @notice Emits `PolicyUninstalled` when permanently disabling a pre-install policyId (binding-mode).
    ///
    /// @param configSeed Seed used to build the policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_emitsPolicyUninstalled_bindingMode_preInstall(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(configSeed);
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, salt);
        bytes32 policyId = policyManager.getPolicyId(binding);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding, policy: address(0), policyId: bytes32(0), policyConfig: policyConfig, uninstallData: ""
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyUninstalled(policyId, address(account), address(callPolicy));
        vm.prank(address(account));
        policyManager.uninstall(payload);
    }

    /// @notice Uninstall is idempotent: uninstalling an already-uninstalled policyId is a no-op.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_isIdempotent_whenAlreadyUninstalled_noHookNoEvent(bytes32 configSeed, uint256 salt) public {
        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(callPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        vm.recordLogs();
        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// @notice Account can always uninstall an installed instance even if the policy hook reverts.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_accountEscapeHatch_installedLifecycle_policyIdMode(bytes32 configSeed, uint256 salt) public {
        (bytes32 policyId, bytes memory policyConfig) =
            _installPolicy(address(revertPolicy), abi.encode(configSeed), salt);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0),
                policy: address(0),
                validAfter: 0,
                validUntil: 0,
                salt: 0,
                policyConfigHash: bytes32(0)
            }),
            policy: address(revertPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(revertPolicy), policyId));
    }

    /// @notice Account can always uninstall an installed instance even if the policy hook reverts.
    ///
    /// @param configSeed Seed used to build the policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_accountEscapeHatch_installedLifecycle_bindingMode(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(configSeed);
        PolicyManager.PolicyBinding memory binding = _binding(address(revertPolicy), policyConfig, salt);

        vm.prank(address(account));
        bytes32 policyId = policyManager.install(binding, policyConfig);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding, policy: address(0), policyId: bytes32(0), policyConfig: policyConfig, uninstallData: ""
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(revertPolicy), policyId));
    }

    /// @notice In binding-mode installed lifecycle, uninstall uses the stored record account (not the payload binding account).
    ///
    /// @param configSeed Seed used to build the policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_bindingMode_installedLifecycle_usesStoredRecordAccount(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(configSeed);
        (, bytes memory policyConfigCopy) = _installPolicy(address(recordPolicy), policyConfig, salt);

        PolicyManager.PolicyBinding memory binding = _binding(address(recordPolicy), policyConfigCopy, salt);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding,
            policy: address(0),
            policyId: bytes32(0),
            policyConfig: policyConfigCopy,
            uninstallData: ""
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertEq(recordPolicy.lastUninstallAccount(), address(account));
    }
}
