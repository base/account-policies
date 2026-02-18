// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title UninstallTest
///
/// @notice Test contract for `AOAPolicy._onUninstall` authorization logic.
///
/// @dev Tests call `policy.onUninstall` directly (pranked as the PolicyManager) to isolate AOA
///      authorization from the PolicyManager's try/catch wrapper, enabling specific error assertions.
contract UninstallTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }

    // =============================================================
    // Installed lifecycle: non-account uninstall with executor sig
    // =============================================================

    /// @notice Reverts when the non-account caller provides a config that doesn't match the stored hash.
    ///
    /// @param relayer Non-account relayer address.
    /// @param wrongConfigSuffix Arbitrary bytes that produce a different config hash.
    function test_reverts_whenNonAccount_andConfigHashMismatch(address relayer, bytes calldata wrongConfigSuffix)
        public
    {
        vm.assume(relayer != address(account));

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory wrongConfig = abi.encode(AOAPolicy.AOAConfig({executor: executor}), wrongConfigSuffix);
        vm.assume(keccak256(wrongConfig) != keccak256(policyConfig));

        bytes memory sig = _signUninstall(policyId, keccak256(policyConfig), 0);
        bytes memory uninstallData = abi.encode(sig, uint256(0));

        vm.expectRevert(
            abi.encodeWithSelector(
                AOAPolicy.PolicyConfigHashMismatch.selector, keccak256(wrongConfig), keccak256(policyConfig)
            )
        );
        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), wrongConfig, uninstallData, relayer);
    }

    /// @notice Reverts when the non-account caller provides an invalid executor signature.
    ///
    /// @param relayer Non-account relayer address.
    /// @param badSig Arbitrary bytes that do not form a valid executor uninstall signature.
    function test_reverts_whenNonAccount_andInvalidExecutorSignature(address relayer, bytes calldata badSig) public {
        vm.assume(relayer != address(account));

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory uninstallData = abi.encode(badSig, uint256(0));

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.Unauthorized.selector, relayer));
        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), policyConfig, uninstallData, relayer);
    }

    /// @notice Reverts when the non-account caller's uninstall signature has expired.
    ///
    /// @param deadline Non-zero deadline that will be exceeded.
    /// @param relayer Non-account relayer address.
    function test_reverts_whenNonAccount_andSignatureExpired(uint256 deadline, address relayer) public {
        vm.assume(relayer != address(account));
        deadline = bound(deadline, 1, type(uint256).max - 1);
        vm.warp(deadline + 1);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory sig = _signUninstall(policyId, keccak256(policyConfig), deadline);
        bytes memory uninstallData = abi.encode(sig, deadline);

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.SignatureExpired.selector, block.timestamp, deadline));
        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), policyConfig, uninstallData, relayer);
    }

    // =============================================================
    // Account-initiated uninstall (caller == account)
    // =============================================================

    /// @notice Account can uninstall without providing config or executor signature.
    ///
    /// @param policyConfigArg Arbitrary config bytes (ignored by the account fast-path).
    /// @param uninstallData Arbitrary uninstall data (ignored by the account fast-path).
    function test_accountCanUninstall_withoutConfig(bytes calldata policyConfigArg, bytes calldata uninstallData)
        public
    {
        bytes32 policyId = policyManager.getPolicyId(binding);

        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), policyConfigArg, uninstallData, address(account));

        assertEq(policy.uninstallCalls(), 1);
        assertEq(policy.lastUninstallPolicyId(), policyId);
        assertEq(policy.lastUninstallAccount(), address(account));
        assertEq(policy.lastUninstallCaller(), address(account));
    }

    /// @notice Non-account caller can uninstall with a valid executor uninstall signature.
    ///
    /// @param relayer Non-account relayer address.
    function test_nonAccountCanUninstall_withValidExecutorSignature(address relayer) public {
        vm.assume(relayer != address(account));

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory sig = _signUninstall(policyId, keccak256(policyConfig), 0);
        bytes memory uninstallData = abi.encode(sig, uint256(0));

        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), policyConfig, uninstallData, relayer);

        assertEq(policy.uninstallCalls(), 1);
        assertEq(policy.lastUninstallPolicyId(), policyId);
        assertEq(policy.lastUninstallAccount(), address(account));
        assertEq(policy.lastUninstallCaller(), executor);
    }

    // =============================================================
    // Pre-install uninstallation (permanent disable before install)
    // =============================================================

    /// @notice Reverts when pre-install uninstall has an invalid executor signature.
    ///
    /// @param relayer Non-account relayer address.
    /// @param salt Salt for deriving a fresh (never-installed) policyId.
    /// @param badSig Arbitrary bytes that do not form a valid executor uninstall signature.
    function test_reverts_whenPreInstallUninstall_andInvalidExecutorSignature(
        address relayer,
        uint256 salt,
        bytes calldata badSig
    ) public {
        vm.assume(relayer != address(account));
        salt = bound(salt, 1, type(uint256).max);

        PolicyManager.PolicyBinding memory freshBinding = _binding(policyConfig, salt);
        bytes32 freshPolicyId = policyManager.getPolicyId(freshBinding);
        bytes memory uninstallData = abi.encode(badSig, uint256(0));

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.Unauthorized.selector, relayer));
        vm.prank(address(policyManager));
        policy.onUninstall(freshPolicyId, address(account), policyConfig, uninstallData, relayer);
    }

    /// @notice Reverts when pre-install uninstall signature has expired.
    ///
    /// @param deadline Non-zero deadline that will be exceeded.
    /// @param salt Salt for deriving a fresh (never-installed) policyId.
    /// @param relayer Non-account relayer address.
    function test_reverts_whenPreInstallUninstall_andSignatureExpired(uint256 deadline, uint256 salt, address relayer)
        public
    {
        vm.assume(relayer != address(account));
        salt = bound(salt, 1, type(uint256).max);
        deadline = bound(deadline, 1, type(uint256).max - 1);
        vm.warp(deadline + 1);

        PolicyManager.PolicyBinding memory freshBinding = _binding(policyConfig, salt);
        bytes32 freshPolicyId = policyManager.getPolicyId(freshBinding);
        bytes memory sig = _signUninstall(freshPolicyId, keccak256(policyConfig), deadline);
        bytes memory uninstallData = abi.encode(sig, deadline);

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.SignatureExpired.selector, block.timestamp, deadline));
        vm.prank(address(policyManager));
        policy.onUninstall(freshPolicyId, address(account), policyConfig, uninstallData, relayer);
    }

    /// @notice Pre-install uninstallation succeeds with a valid executor signature (permanent disable).
    ///
    /// @param salt Salt for deriving a fresh (never-installed) policyId.
    /// @param relayer Non-account relayer address.
    function test_preInstallUninstall_withValidExecutorSignature(uint256 salt, address relayer) public {
        vm.assume(relayer != address(account));
        salt = bound(salt, 1, type(uint256).max);

        PolicyManager.PolicyBinding memory freshBinding = _binding(policyConfig, salt);
        bytes32 freshPolicyId = policyManager.getPolicyId(freshBinding);
        bytes memory sig = _signUninstall(freshPolicyId, keccak256(policyConfig), 0);
        bytes memory uninstallData = abi.encode(sig, uint256(0));

        vm.prank(address(policyManager));
        policy.onUninstall(freshPolicyId, address(account), policyConfig, uninstallData, relayer);

        assertEq(policy.uninstallCalls(), 1);
        assertEq(policy.lastUninstallPolicyId(), freshPolicyId);
        assertEq(policy.lastUninstallAccount(), address(account));
        assertEq(policy.lastUninstallCaller(), executor);
    }
}
