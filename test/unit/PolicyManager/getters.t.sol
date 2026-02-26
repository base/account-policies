// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";

/// @title GettersTest
///
/// @notice Test contract for `PolicyManager` view/pure getters and read helpers.
contract GettersTest is PolicyManagerTestBase {
    /// @dev Maximum length for fuzzed arrays to keep fuzz runs fast.
    uint256 internal constant MAX_ARRAY_LEN = 16;
    /// @dev Base timestamp used for warp-based tests.
    uint40 internal constant WARP_BASE_TIMESTAMP = 1_000_000;

    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Installs `callPolicy` for `account` with the provided binding parameters.
    ///
    /// @param policyConfig Policy config bytes used for installation (hashed into the binding).
    /// @param salt Salt used to derive a distinct `policyId`.
    /// @param validAfter Lower-bound timestamp (seconds) for the binding.
    /// @param validUntil Upper-bound timestamp (seconds) for the binding.
    ///
    /// @return policyId Deterministic binding identifier derived from the provided binding inputs.
    /// @return binding The binding used for installation.
    function _installCallPolicy(bytes memory policyConfig, uint256 salt, uint40 validAfter, uint40 validUntil)
        internal
        returns (bytes32 policyId, PolicyManager.PolicyBinding memory binding)
    {
        binding = PolicyManager.PolicyBinding({
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

    /// @notice Uninstalls a policyId-mode installed binding via the account.
    ///
    /// @param policyId Installed policy identifier.
    /// @param policyConfig Config preimage forwarded to the policy uninstall hook.
    function _uninstallInstalledPolicy(bytes32 policyId, bytes memory policyConfig) internal {
        PolicyManager.PolicyBinding memory emptyBinding;
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: emptyBinding,
            policy: address(callPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });
        vm.prank(address(account));
        policyManager.uninstall(payload);
    }

    // =============================================================
    // policies(policy, policyId)
    // =============================================================

    /// @notice Returns all-zero fields when the policyId has never been seen.
    function test_policies_returnsZeros_whenNeverInstalled() public {
        (bool installed, bool uninstalled, address recordAccount, uint40 validAfter, uint40 validUntil) =
            policyManager.policies(address(callPolicy), bytes32(uint256(1)));
        assertFalse(installed);
        assertFalse(uninstalled);
        assertEq(recordAccount, address(0));
        assertEq(validAfter, 0);
        assertEq(validUntil, 0);
    }

    /// @notice Returns stored binding fields after install.
    function test_policies_returnsRecord_afterInstall() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId, PolicyManager.PolicyBinding memory binding) = _installCallPolicy(policyConfig, 0, 0, 0);

        (bool installed, bool uninstalled, address recordAccount, uint40 validAfter, uint40 validUntil) =
            policyManager.policies(address(callPolicy), policyId);
        assertTrue(installed);
        assertFalse(uninstalled);
        assertEq(recordAccount, binding.account);
        assertEq(validAfter, binding.validAfter);
        assertEq(validUntil, binding.validUntil);
    }

    /// @notice Returns `uninstalled = true` after uninstall.
    function test_policies_returnsUninstalled_afterUninstall() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);

        _uninstallInstalledPolicy(policyId, policyConfig);

        (, bool uninstalled,,,) = policyManager.policies(address(callPolicy), policyId);
        assertTrue(uninstalled);
    }

    // =============================================================
    // getAccountsForPolicies
    // =============================================================

    /// @notice Returns an array of the same length as `policyIds`.
    function test_getAccountsForPolicies_returnsSameLength(uint256 len) public {
        len = bound(len, 0, MAX_ARRAY_LEN);
        bytes32[] memory policyIds = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            policyIds[i] = bytes32(i + 1);
        }

        address[] memory accounts = policyManager.getAccountsForPolicies(address(callPolicy), policyIds);
        assertEq(accounts.length, len);
    }

    /// @notice Returns zero address for policyIds that have never been installed.
    function test_getAccountsForPolicies_returnsZeroForUnknownPolicyIds(bytes32 policyId) public {
        bytes32[] memory policyIds = new bytes32[](1);
        policyIds[0] = policyId;

        address[] memory accounts = policyManager.getAccountsForPolicies(address(callPolicy), policyIds);
        assertEq(accounts.length, 1);
        assertEq(accounts[0], address(0));
    }

    /// @notice Returns the stored account for installed policyIds.
    function test_getAccountsForPolicies_returnsAccountForInstalledPolicyIds() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyIdA,) = _installCallPolicy(policyConfig, 0, 0, 0);
        (bytes32 policyIdB,) = _installCallPolicy(policyConfig, 1, 0, 0);

        bytes32[] memory policyIds = new bytes32[](2);
        policyIds[0] = policyIdA;
        policyIds[1] = policyIdB;

        address[] memory accounts = policyManager.getAccountsForPolicies(address(callPolicy), policyIds);
        assertEq(accounts.length, 2);
        assertEq(accounts[0], address(account));
        assertEq(accounts[1], address(account));
    }

    // =============================================================
    // getPolicyRecords
    // =============================================================

    /// @notice Returns arrays with the same length as `policyIds`.
    function test_getPolicyRecords_returnsSameLength(uint256 len) public {
        len = bound(len, 0, MAX_ARRAY_LEN);
        bytes32[] memory policyIds = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            policyIds[i] = bytes32(i + 1);
        }

        (
            bool[] memory installed,
            bool[] memory uninstalled,
            address[] memory recordAccount,
            uint40[] memory validAfter,
            uint40[] memory validUntil
        ) = policyManager.getPolicyRecords(address(callPolicy), policyIds);

        assertEq(installed.length, len);
        assertEq(uninstalled.length, len);
        assertEq(recordAccount.length, len);
        assertEq(validAfter.length, len);
        assertEq(validUntil.length, len);
    }

    /// @notice Returns default (zero) record fields for unknown policyIds.
    function test_getPolicyRecords_returnsZerosForUnknownPolicyIds(bytes32 policyId) public {
        bytes32[] memory policyIds = new bytes32[](1);
        policyIds[0] = policyId;

        (
            bool[] memory installed,
            bool[] memory uninstalled,
            address[] memory recordAccount,
            uint40[] memory validAfter,
            uint40[] memory validUntil
        ) = policyManager.getPolicyRecords(address(callPolicy), policyIds);

        assertEq(installed.length, 1);
        assertFalse(installed[0]);
        assertFalse(uninstalled[0]);
        assertEq(recordAccount[0], address(0));
        assertEq(validAfter[0], 0);
        assertEq(validUntil[0], 0);
    }

    /// @notice Returns stored record fields for installed policyIds.
    function test_getPolicyRecords_returnsRecordForInstalledPolicyIds() public {
        uint40 validAfter = WARP_BASE_TIMESTAMP + 1;
        uint40 validUntil = WARP_BASE_TIMESTAMP + 10;
        uint40 installTs = WARP_BASE_TIMESTAMP + 5;
        vm.warp(uint256(installTs));

        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId, PolicyManager.PolicyBinding memory binding) =
            _installCallPolicy(policyConfig, 0, validAfter, validUntil);

        bytes32[] memory policyIds = new bytes32[](1);
        policyIds[0] = policyId;

        (
            bool[] memory installed,
            bool[] memory uninstalled,
            address[] memory recordAccount,
            uint40[] memory recordValidAfter,
            uint40[] memory recordValidUntil
        ) = policyManager.getPolicyRecords(address(callPolicy), policyIds);

        assertEq(installed.length, 1);
        assertTrue(installed[0]);
        assertFalse(uninstalled[0]);
        assertEq(recordAccount[0], binding.account);
        assertEq(recordValidAfter[0], binding.validAfter);
        assertEq(recordValidUntil[0], binding.validUntil);
    }

    /// @notice Returns `uninstalled = true` for uninstalled policyIds.
    function test_getPolicyRecords_returnsUninstalledForUninstalledPolicyIds() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);

        _uninstallInstalledPolicy(policyId, policyConfig);

        bytes32[] memory policyIds = new bytes32[](1);
        policyIds[0] = policyId;

        (bool[] memory installed, bool[] memory uninstalled,,,) =
            policyManager.getPolicyRecords(address(callPolicy), policyIds);
        assertTrue(installed[0]);
        assertTrue(uninstalled[0]);
    }

    // =============================================================
    // getPolicyId
    // =============================================================

    /// @notice Produces the same policyId for the same binding inputs.
    function test_getPolicyId_isDeterministic() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);

        bytes32 policyIdA = policyManager.getPolicyId(binding);
        bytes32 policyIdB = policyManager.getPolicyId(binding);
        assertEq(policyIdA, policyIdB);
    }

    /// @notice Changing `salt` changes the policyId.
    function test_getPolicyId_changesWithSalt(uint256 saltA, uint256 saltB) public {
        vm.assume(saltA != saltB);

        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory bindingA = _binding(address(callPolicy), policyConfig, saltA);
        PolicyManager.PolicyBinding memory bindingB = _binding(address(callPolicy), policyConfig, saltB);

        bytes32 policyIdA = policyManager.getPolicyId(bindingA);
        bytes32 policyIdB = policyManager.getPolicyId(bindingB);
        assertTrue(policyIdA != policyIdB);
    }

    /// @notice Changing `policyConfig` changes the policyId.
    function test_getPolicyId_changesWithPolicyConfig(bytes32 policyConfigSeedA, bytes32 policyConfigSeedB) public {
        if (policyConfigSeedB == policyConfigSeedA) policyConfigSeedB = policyConfigSeedA ^ bytes32(uint256(1));

        PolicyManager.PolicyBinding memory bindingA = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            policyConfig: abi.encode(policyConfigSeedA),
            validAfter: 0,
            validUntil: 0,
            salt: 0
        });
        PolicyManager.PolicyBinding memory bindingB = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            policyConfig: abi.encode(policyConfigSeedB),
            validAfter: 0,
            validUntil: 0,
            salt: 0
        });

        bytes32 policyIdA = policyManager.getPolicyId(bindingA);
        bytes32 policyIdB = policyManager.getPolicyId(bindingB);
        assertTrue(policyIdA != policyIdB);
    }

    /// @notice Changing the validity window changes the policyId.
    function test_getPolicyId_changesWithValidityWindow(uint40 validAfter, uint40 validUntil) public {
        uint40 validAfterB = validAfter == type(uint40).max ? validAfter - 1 : validAfter + 1;

        PolicyManager.PolicyBinding memory bindingA = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            policyConfig: bytes(""),
            validAfter: validAfter,
            validUntil: validUntil,
            salt: 0
        });
        PolicyManager.PolicyBinding memory bindingB = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            policyConfig: bytes(""),
            validAfter: validAfterB,
            validUntil: validUntil,
            salt: 0
        });

        bytes32 policyIdA = policyManager.getPolicyId(bindingA);
        bytes32 policyIdB = policyManager.getPolicyId(bindingB);
        assertTrue(policyIdA != policyIdB);
    }

    /// @notice Matches the `POLICY_BINDING_TYPEHASH` field order (regression test against accidental reorder).
    function test_getPolicyId_matchesTypehashFieldOrder() public {
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            policyConfig: abi.encode(bytes32(uint256(1))),
            validAfter: 2,
            validUntil: 3,
            salt: 4
        });

        bytes32 expected = keccak256(
            abi.encode(
                policyManager.POLICY_BINDING_TYPEHASH(),
                binding.account,
                binding.policy,
                keccak256(binding.policyConfig),
                binding.validAfter,
                binding.validUntil,
                binding.salt
            )
        );
        assertEq(policyManager.getPolicyId(binding), expected);
    }

    // =============================================================
    // isPolicyInstalled / isPolicyUninstalled / isPolicyActive / isPolicyActiveNow
    // =============================================================

    /// @notice Returns false when the policyId has never been installed.
    function test_isPolicyInstalled_returnsFalse_whenNeverInstalled() public {
        assertFalse(policyManager.isPolicyInstalled(address(callPolicy), bytes32(uint256(1))));
    }

    /// @notice Returns true after install (even if later uninstalled).
    function test_isPolicyInstalled_returnsTrue_afterInstall_evenIfLaterUninstalled() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);

        _uninstallInstalledPolicy(policyId, policyConfig);
        assertTrue(policyManager.isPolicyInstalled(address(callPolicy), policyId));
    }

    /// @notice Returns false when the policyId has never been uninstalled.
    function test_isPolicyUninstalled_returnsFalse_whenNeverUninstalled() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);
        assertFalse(policyManager.isPolicyUninstalled(address(callPolicy), policyId));
    }

    /// @notice Returns true after uninstall.
    function test_isPolicyUninstalled_returnsTrue_afterUninstall() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);

        _uninstallInstalledPolicy(policyId, policyConfig);
        assertTrue(policyManager.isPolicyUninstalled(address(callPolicy), policyId));
    }

    /// @notice Returns false when the policyId has never been installed.
    function test_isPolicyActive_returnsFalse_whenNeverInstalled() public {
        assertFalse(policyManager.isPolicyActive(address(callPolicy), bytes32(uint256(1))));
    }

    /// @notice Returns true after install.
    function test_isPolicyActive_returnsTrue_afterInstall() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);
        assertTrue(policyManager.isPolicyActive(address(callPolicy), policyId));
    }

    /// @notice Returns false after uninstall.
    function test_isPolicyActive_returnsFalse_afterUninstall() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);

        _uninstallInstalledPolicy(policyId, policyConfig);
        assertFalse(policyManager.isPolicyActive(address(callPolicy), policyId));
    }

    /// @notice Returns false when the policyId has never been installed.
    function test_isPolicyActiveNow_returnsFalse_whenNeverInstalled() public {
        assertFalse(policyManager.isPolicyActiveNow(address(callPolicy), bytes32(uint256(1))));
    }

    /// @notice Returns false when the policy is uninstalled.
    function test_isPolicyActiveNow_returnsFalse_whenUninstalled() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, 0);

        _uninstallInstalledPolicy(policyId, policyConfig);
        assertFalse(policyManager.isPolicyActiveNow(address(callPolicy), policyId));
    }

    /// @notice Returns false when current timestamp is before `validAfter`.
    function test_isPolicyActiveNow_returnsFalse_whenBeforeValidAfter(uint40 validAfter) public {
        validAfter = uint40(bound(uint256(validAfter), 1, uint256(type(uint40).max)));

        bytes memory policyConfig = abi.encode(bytes32(0));
        vm.warp(uint256(validAfter));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, validAfter, 0);

        vm.warp(uint256(validAfter - 1));
        assertFalse(policyManager.isPolicyActiveNow(address(callPolicy), policyId));
    }

    /// @notice Returns false when current timestamp is at/after `validUntil`.
    function test_isPolicyActiveNow_returnsFalse_whenAfterValidUntil(uint40 validUntil) public {
        validUntil = uint40(bound(uint256(validUntil), 1, uint256(type(uint40).max)));

        bytes memory policyConfig = abi.encode(bytes32(0));
        vm.warp(uint256(validUntil - 1));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, validUntil);

        vm.warp(uint256(validUntil));
        assertFalse(policyManager.isPolicyActiveNow(address(callPolicy), policyId));
    }

    /// @notice Returns true when installed, not uninstalled, and within the validity window.
    function test_isPolicyActiveNow_returnsTrue_whenWithinValidityWindow() public {
        uint40 validAfter = WARP_BASE_TIMESTAMP + 1;
        uint40 validUntil = WARP_BASE_TIMESTAMP + 10;
        uint40 installTs = WARP_BASE_TIMESTAMP + 5;
        vm.warp(uint256(installTs));

        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, validAfter, validUntil);

        assertTrue(policyManager.isPolicyActiveNow(address(callPolicy), policyId));
    }

    // =============================================================
    // isPolicyActiveAt
    // =============================================================

    /// @notice Returns false when the policyId has never been installed.
    function test_isPolicyActiveAt_returnsFalse_whenNeverInstalled() public {
        assertFalse(policyManager.isPolicyActiveAt(address(callPolicy), bytes32(uint256(1)), uint40(block.timestamp)));
    }

    /// @notice Returns false when the queried timestamp is before `validAfter`.
    ///
    /// @param validAfter Fuzzed validAfter bound.
    function test_isPolicyActiveAt_returnsFalse_whenBeforeValidAfter(uint40 validAfter) public {
        validAfter = uint40(bound(uint256(validAfter), 2, uint256(type(uint40).max)));

        bytes memory policyConfig = abi.encode(bytes32(0));
        vm.warp(uint256(validAfter));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, validAfter, 0);

        assertFalse(policyManager.isPolicyActiveAt(address(callPolicy), policyId, validAfter - 1));
    }

    /// @notice Returns false when the queried timestamp is at/after `validUntil`.
    ///
    /// @param validUntil Fuzzed validUntil bound.
    function test_isPolicyActiveAt_returnsFalse_whenAtOrAfterValidUntil(uint40 validUntil) public {
        validUntil = uint40(bound(uint256(validUntil), 1, uint256(type(uint40).max)));

        bytes memory policyConfig = abi.encode(bytes32(0));
        vm.warp(uint256(validUntil - 1));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, 0, validUntil);

        assertFalse(policyManager.isPolicyActiveAt(address(callPolicy), policyId, validUntil));
    }

    /// @notice Returns true when the queried timestamp is within the validity window.
    function test_isPolicyActiveAt_returnsTrue_whenWithinWindow() public {
        uint40 validAfter = WARP_BASE_TIMESTAMP + 1;
        uint40 validUntil = WARP_BASE_TIMESTAMP + 10;
        vm.warp(uint256(validAfter));

        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, validAfter, validUntil);

        assertTrue(policyManager.isPolicyActiveAt(address(callPolicy), policyId, WARP_BASE_TIMESTAMP + 5));
    }

    /// @notice Allows checking a future timestamp without warping.
    function test_isPolicyActiveAt_canCheckFutureTimestamp() public {
        uint40 validAfter = WARP_BASE_TIMESTAMP;
        uint40 validUntil = WARP_BASE_TIMESTAMP + 100;
        vm.warp(uint256(validAfter));

        bytes memory policyConfig = abi.encode(bytes32(0));
        (bytes32 policyId,) = _installCallPolicy(policyConfig, 0, validAfter, validUntil);

        assertTrue(policyManager.isPolicyActiveAt(address(callPolicy), policyId, WARP_BASE_TIMESTAMP + 50));
        assertFalse(policyManager.isPolicyActiveAt(address(callPolicy), policyId, WARP_BASE_TIMESTAMP + 100));
    }
}

