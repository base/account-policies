// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";
import {CallForwardingPolicy} from "../../lib/testPolicies/CallForwardingPolicy.sol";
import {MockCoinbaseSmartWallet} from "../../lib/mocks/MockCoinbaseSmartWallet.sol";
import {RecordingReplacePolicy} from "../../lib/testPolicies/RecordingReplacePolicy.sol";
import {RevertOnReplacePolicy} from "../../lib/testPolicies/RevertOnReplacePolicy.sol";
import {RevertOnUninstallForReplacePolicy} from "../../lib/testPolicies/RevertOnUninstallForReplacePolicy.sol";
import {RevertingReceiver} from "../../lib/mocks/RevertingReceiver.sol";

/// @title ReplaceWithSignatureTest
///
/// @notice Test contract for `PolicyManager.replaceWithSignature`.
contract ReplaceWithSignatureTest is PolicyManagerTestBase {
    /// @dev Maximum length for fuzzed `bytes` inputs (calldata) to keep fuzz runs fast.
    uint256 internal constant MAX_BYTES_LEN = 256;
    /// @dev Base timestamp used when warping for validity-window and deadline tests.
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

    /// @notice Produces an ERC-6492-wrapped EIP-712 signature over the replace typed digest.
    ///
    /// @param accountAddr Account address (signer) in the typed data.
    /// @param oldPolicy Old policy contract address in the typed data.
    /// @param oldPolicyId Old policy identifier in the typed data.
    /// @param oldPolicyConfig Old policy config bytes (hashed into the signed digest).
    /// @param newPolicyId New policy identifier in the typed data.
    /// @param deadline Signature deadline (seconds) in the typed data.
    ///
    /// @return ERC-6492-wrapped signature bytes.
    function _signReplace(
        address accountAddr,
        address oldPolicy,
        bytes32 oldPolicyId,
        bytes memory oldPolicyConfig,
        bytes32 newPolicyId,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                policyManager.REPLACE_POLICY_TYPEHASH(),
                accountAddr,
                oldPolicy,
                oldPolicyId,
                keccak256(oldPolicyConfig),
                newPolicyId,
                deadline
            )
        );
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

    /// @notice Installs `callPolicy` for `account` using the given config + binding parameters.
    ///
    /// @dev The manager call is authorized via `vm.prank(account)`.
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

    /// @notice Performs a replacement via direct account call (no signature).
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
                oldPolicy: oldPolicy,
                oldPolicyId: oldPolicyId,
                oldPolicyConfig: oldPolicyConfig,
                replaceData: "",
                newBinding: newBinding
            });
        vm.prank(newBinding.account);
        return policyManager.replace(payload);
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the old policy address has no deployed code.
    ///
    /// @dev Expects `PolicyManager.PolicyNotContract`. Installs a policy, then clears its code via
    ///      `vm.etch` so that `_uninstallForReplace` sees a non-contract and reverts.
    function test_reverts_whenOldPolicyNotContract() public {
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

        vm.etch(address(oldPolicy), "");

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(oldPolicy), oldPolicyId, oldConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(oldPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert();
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice Reverts when the new policy address has no deployed code.
    ///
    /// @dev Expects `PolicyManager.PolicyNotContract`.
    ///
    /// @param newPolicy Fuzzed non-contract address for the new policy.
    function test_reverts_whenNewPolicyNotContract(address newPolicy) public {
        vm.assume(newPolicy != address(0));
        vm.assume(newPolicy.code.length == 0);

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: newPolicy,
            validAfter: 0,
            validUntil: 0,
            salt: DEFAULT_NEW_SALT,
            policyConfig: abi.encode(DEFAULT_NEW_CONFIG_SEED)
        });
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert();
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice Reverts when the replace payload is invalid (e.g., zero policy addresses, invalid ids).
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenReplacePayloadInvalid() public {
        (bytes32 oldPolicyId,) = _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(address(account), address(0), oldPolicyId, "", newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(0),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: "",
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice Reverts when the signature is past its deadline.
    ///
    /// @dev Expects `PolicyManager.DeadlineExpired`.
    ///
    /// @param deadlineSeed Seed used to pick a deadline strictly before current timestamp (no discard).
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_reverts_whenDeadlineExpired(uint256 deadlineSeed, bytes32 configSeed, uint256 salt) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint256 nowTs = block.timestamp;
        uint256 deadline = bound(deadlineSeed, 1, nowTs - 1);

        (bytes32 oldPolicyId,) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(
            address(account), address(callPolicy), oldPolicyId, abi.encode(configSeed), newPolicyId, deadline
        );

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: abi.encode(configSeed),
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.DeadlineExpired.selector, uint256(nowTs), deadline));
        policyManager.replaceWithSignature(payload, userSig, deadline, bytes(""));
    }

    /// @notice Reverts when the account signature is invalid.
    ///
    /// @dev Expects `PolicyManager.InvalidSignature`.
    ///
    /// @param userSig Arbitrary invalid signature bytes (length bounded to keep fuzz fast).
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_reverts_whenInvalidSignature(bytes memory userSig, bytes32 configSeed, uint256 salt) public {
        vm.assume(userSig.length <= MAX_BYTES_LEN);

        (bytes32 oldPolicyId,) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: abi.encode(configSeed),
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(PolicyManager.InvalidSignature.selector);
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
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
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(address(account), address(callPolicy), oldPolicyId, "", newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: "",
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyNotInstalled.selector, oldPolicyId));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice Reverts when the old policyId is already uninstalled.
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenOldPolicyIsDisabled() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory emptyBinding;
        PolicyManager.UninstallPayload memory uninstallPayload = PolicyManager.UninstallPayload({
            binding: emptyBinding,
            policy: address(callPolicy),
            policyId: oldPolicyId,
            policyConfig: oldPolicyConfig,
            uninstallData: ""
        });
        policyManager.uninstall(uninstallPayload);

        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(address(account), address(callPolicy), oldPolicyId, "", newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: "",
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, oldPolicyId));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
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
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, abi.encode(bytes32(0)), newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: abi.encode(bytes32(0)),
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(PolicyManager.InvalidPayload.selector);
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
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

        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyAlreadyInstalled.selector, newPolicyId));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice Reverts when installing the new policy outside its validity window.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter` / `PolicyManager.AfterValidUntil`.
    ///
    /// @param validAfterSeed Seed used to pick a validAfter strictly after current timestamp.
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the old binding (hashed into `policyId`).
    function test_reverts_whenNewBindingOutsideValidityWindow(uint40 validAfterSeed, bytes32 configSeed, uint256 salt)
        public
    {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint256 nowTs = block.timestamp;

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
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
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.BeforeValidAfter.selector, uint40(nowTs), validAfter));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
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
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(RevertOnReplacePolicy.OnReplaceReverted.selector);
        vm.prank(address(account));
        policyManager.replace(payload);
    }

    /// @notice Reverts when the new policyId is disabled (pre-install uninstallation).
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`. New binding's policyId is pre-disabled via
    ///      binding-mode uninstall before install; _installForReplace hits PolicyIsDisabled.
    function test_reverts_whenExecutionAfterReplace_andNewPolicyIsDisabled() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);

        vm.prank(address(account));
        policyManager.uninstall(
            PolicyManager.UninstallPayload({
                binding: newBinding,
                policy: address(0),
                policyId: bytes32(0),
                policyConfig: abi.encode(DEFAULT_NEW_CONFIG_SEED),
                uninstallData: ""
            })
        );

        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, newPolicyId));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice Reverts when executing after replace outside the new binding validity window.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter` / `PolicyManager.AfterValidUntil`.
    ///
    /// @param validUntilSeed Seed used to pick a validUntil strictly after current timestamp.
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the old binding (hashed into `policyId`).
    function test_reverts_whenExecutionAfterReplace_outsideValidityWindow(
        uint40 validUntilSeed,
        bytes32 configSeed,
        uint256 salt
    ) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint256 nowTs = block.timestamp;
        uint40 validUntil = uint40(bound(uint256(validUntilSeed), nowTs + 1, uint256(type(uint40).max)));

        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        bytes memory newConfig = abi.encode(DEFAULT_NEW_CONFIG_SEED);
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            validAfter: 0,
            validUntil: validUntil,
            salt: DEFAULT_NEW_SALT,
            policyConfig: newConfig
        });
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        _replaceViaAccount(address(callPolicy), oldPolicyId, oldPolicyConfig, newBinding);

        vm.warp(uint256(validUntil));

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.AfterValidUntil.selector, validUntil, validUntil));
        policyManager.replaceWithSignature(payload, userSig, 0, abi.encode(f));
    }

    /// @notice Bubbles a revert when the policy's `onExecute` hook reverts (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andPolicyOnExecuteReverts() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: true,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.expectRevert(CallForwardingPolicy.OnExecuteReverted.selector);
        policyManager.replaceWithSignature(payload, userSig, 0, executionData);
    }

    /// @notice Bubbles a revert when the account call fails (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andAccountCallReverts() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        RevertingReceiver revertingReceiver = new RevertingReceiver();
        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(revertingReceiver),
            value: 0,
            data: abi.encodeWithSelector(revertingReceiver.ping.selector),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(RevertingReceiver.ReceiverReverted.selector);
        policyManager.replaceWithSignature(payload, userSig, 0, executionData);
    }

    /// @notice Bubbles a revert when the post-call fails (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andPostCallReverts() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.RevertPost
        });
        bytes memory executionData = abi.encode(f);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(abi.encodeWithSelector(CallForwardingPolicy.PostCallReverted.selector, newPolicyId));
        policyManager.replaceWithSignature(payload, userSig, 0, executionData);
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
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyUninstalled(oldPolicyId, address(account), address(callPolicy));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice Emits `PolicyInstalled` for the new policy instance.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    function test_emitsPolicyInstalled_forNewPolicy(bytes32 configSeed, uint256 salt) public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyInstalled(newPolicyId, address(account), address(callPolicy));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
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
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyReplaced(
            oldPolicyId, newPolicyId, address(account), address(callPolicy), address(callPolicy)
        );
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
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
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(oldPolicy), oldPolicyId, oldConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(oldPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldConfig,
            replaceData: "",
            newBinding: newBinding
        });

        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));

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
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));

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
        bytes memory userSig =
            _signReplace(address(account), address(oldPolicy), oldPolicyId, oldConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(oldPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.prank(address(account));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));

        assertTrue(policyManager.isPolicyActive(address(callPolicy), newPolicyId));
    }

    /// @notice Returns early without requiring a valid signature when end state is already reached and no execution is requested.
    function test_isIdempotent_whenEndStateAlreadyReached_andNoExecution_doesNotRequireValidSig() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);

        _replaceViaAccount(address(callPolicy), oldPolicyId, oldPolicyConfig, newBinding);

        vm.warp(block.timestamp + 1);
        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        bytes32 ret = policyManager.replaceWithSignature(payload, bytes("invalid"), 0, bytes(""));
        assertEq(ret, newPolicyId);
    }

    /// @notice When `executionData` is empty, replaceWithSignature does not execute or emit `PolicyExecuted`.
    function test_whenExecutionDataEmpty_doesNotExecute() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));

        assertEq(receiver.calls(), 0);
    }

    /// @notice Performs execution after a successful replacement when `executionData` is provided.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    function test_executesAfterReplace_whenExecutionDataProvided(bytes32 configSeed, uint256 salt, bytes32 tag) public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        policyManager.replaceWithSignature(payload, userSig, 0, executionData);

        assertEq(receiver.calls(), 1);
        assertEq(receiver.lastTag(), tag);
    }

    /// @notice Emits `PolicyExecuted` after replacement when `executionData` is provided.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    function test_emitsPolicyExecuted_afterReplace_whenExecutionDataProvided(
        bytes32 configSeed,
        uint256 salt,
        bytes32 tag
    ) public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig =
            _signReplace(address(account), address(callPolicy), oldPolicyId, oldPolicyConfig, newPolicyId, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyExecuted(newPolicyId, address(account), address(callPolicy), keccak256(executionData));
        policyManager.replaceWithSignature(payload, userSig, 0, executionData);
    }

    /// @notice When end state is already reached but execution is requested, still requires a valid signature.
    function test_whenEndStateAlreadyReached_andExecutionRequested_requiresValidSig() public {
        (bytes32 oldPolicyId, bytes memory oldPolicyConfig) =
            _installCallPolicy(abi.encode(bytes32(0)), DEFAULT_OLD_SALT, 0, 0);
        PolicyManager.PolicyBinding memory newBinding =
            _binding(address(callPolicy), abi.encode(DEFAULT_NEW_CONFIG_SEED), DEFAULT_NEW_SALT);

        _replaceViaAccount(address(callPolicy), oldPolicyId, oldPolicyConfig, newBinding);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(callPolicy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: oldPolicyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectRevert(PolicyManager.InvalidSignature.selector);
        policyManager.replaceWithSignature(payload, bytes("invalid"), 0, executionData);
    }
}
