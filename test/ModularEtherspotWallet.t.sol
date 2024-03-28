// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {ModuleIsolationHook} from "../src/etherspot/hook/ModuleIsolation.sol";

import "etherspot-prime-contracts/src/modular-etherspot-wallet/modules/MultipleOwnerECDSAValidator.sol";
import "etherspot-prime-contracts/src/modular-etherspot-wallet/wallet/ModularEtherspotWallet.sol";
import "etherspot-prime-contracts/src/modular-etherspot-wallet/wallet/ModularEtherspotWalletFactory.sol";

import "etherspot-prime-contracts/test/foundry/TestAdvancedUtils.t.sol";
import "etherspot-prime-contracts/src/modular-etherspot-wallet/erc7579-ref-impl/test/Bootstrap.t.sol";


import {ECDSA} from "solady/src/utils/ECDSA.sol";

contract MockFallbackHandler1 {
    function onInstall(bytes memory data) public {}

    function onERC721Received(address,address,uint256,bytes calldata) external returns (bytes4) {
        return bytes4(0x12345678);
    }
}

contract ModularEtherspotWalletTest is TestAdvancedUtils {
    address owner2;
    uint256 owner2Key;
    address guardian1;
    uint256 guardian1Key;
    address guardian2;
    uint256 guardian2Key;
    address guardian3;
    uint256 guardian3Key;
    address guardian4;
    uint256 guardian4Key;

    ModuleIsolationHook public testHook;


    function makeBootstrapFallbackConfig(
        address module,
        bytes memory data
    ) public pure returns (BootstrapConfig[] memory config) {
        config = new BootstrapConfig[](1);
        config[0].module = module;
        config[0].data = data;
    }

    function getMEWAndInitCodeCustom(address targetValidator, bytes memory data1, address targetExecutor, bytes memory data2, address targetHook, bytes memory data3, address targetFallback, bytes memory data4)
    internal
    returns (address account, bytes memory initCode)
    {
        // Create config for initial modules
        BootstrapConfig[] memory validators = makeBootstrapConfig(address(targetValidator),
            data1);
        BootstrapConfig[] memory executors = makeBootstrapConfig(address(targetExecutor), data2);
        BootstrapConfig memory hook = _makeBootstrapConfig(address(targetHook), data3);
        BootstrapConfig[] memory fallbacks = makeBootstrapFallbackConfig(address(targetFallback), data4);

        // Create owner
        (owner1, owner1Key) = makeAddrAndKey("owner1");


        // Create initcode and salt to be sent to Factory
        bytes memory _initCode = abi.encode(
            owner1,
            address(bootstrapSingleton),
            abi.encodeCall(
                bootstrapSingleton.initMSA,
                (validators, executors, hook, fallbacks)
            )
        );
        bytes32 salt = keccak256("1");

        // Get address of new account
        account = factory.getAddress(salt, _initCode);

        // Pack the initcode to include in the userOp
        initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(
                factory.createAccount.selector,
                salt,
                _initCode
            )
        );

        // Deal 100 ether to the account
        vm.deal(account, 100 ether);
    }

    function getNonceCustom(
        address account,
        address validator
    ) internal view returns (uint256 nonce) {
        uint192 key = uint192(bytes24(bytes20(address(validator))));
        nonce = entrypoint.getNonce(address(account), key);
    }

    function setUp() public override {
        super.setUp();
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        (guardian1, guardian1Key) = makeAddrAndKey("guardian1");
        (guardian2, guardian2Key) = makeAddrAndKey("guardian2");
        (guardian3, guardian3Key) = makeAddrAndKey("guardian3");
        (guardian4, guardian4Key) = makeAddrAndKey("guardian4");

        testHook = new ModuleIsolationHook();
    }

    function testModuleIsolation_SingleCall() public {
        MockFallbackHandler1 fallbackHandler = new MockFallbackHandler1();
        MultipleOwnerECDSAValidator mockValidator = new MultipleOwnerECDSAValidator();
        (address account, bytes memory initCode) = getMEWAndInitCodeCustom(address(mockValidator), abi.encodePacked(owner1), address(defaultExecutor), "", address(testHook), "", address(0), "");
        uint256 nonce = getNonceCustom(account, address(mockValidator));

        PackedUserOperation memory userOp = getDefaultUserOp();
        userOp.sender = address(account);
        userOp.nonce = nonce;
        userOp.initCode = initCode;
        userOp.callData = "aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd";

        bytes32 hash = entrypoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            owner1Key,
            ECDSA.toEthSignedMessageHash(hash)
        );
        bytes memory signature = abi.encodePacked(r, s, v);

        userOp.signature = signature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entrypoint.handleOps(userOps, payable(address(0x11421)));


        defaultExecutor.executeViaAccount(IERC7579Account(account), address(account), 0, abi.encodeWithSelector(ModularEtherspotWallet.uninstallModule.selector, uint256(1), address(mockValidator), ""));
    }

    function testModuleIsolation_DelegateCall() public {
        MockFallbackHandler1 fallbackHandler = new MockFallbackHandler1();
        MultipleOwnerECDSAValidator mockValidator = new MultipleOwnerECDSAValidator();
        (address account, bytes memory initCode) = getMEWAndInitCodeCustom(address(mockValidator), abi.encodePacked(owner1), address(defaultExecutor), "", address(testHook), "", address(0), "");
        uint256 nonce = getNonceCustom(account, address(mockValidator));

        PackedUserOperation memory userOp = getDefaultUserOp();
        userOp.sender = address(account);
        userOp.nonce = nonce;
        userOp.initCode = initCode;
        userOp.callData = "aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd";

        bytes32 hash = entrypoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            owner1Key,
            ECDSA.toEthSignedMessageHash(hash)
        );
        bytes memory signature = abi.encodePacked(r, s, v);

        userOp.signature = signature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entrypoint.handleOps(userOps, payable(address(0x11421)));


        defaultExecutor.execDelegatecall(IERC7579Account(account), abi.encodeWithSelector(ModularEtherspotWallet.uninstallModule.selector, uint256(1), address(mockValidator), ""));
    }

    function testModuleIsolation_BatchCall() public {
        MockFallbackHandler1 fallbackHandler = new MockFallbackHandler1();
        MultipleOwnerECDSAValidator mockValidator = new MultipleOwnerECDSAValidator();
        (address account, bytes memory initCode) = getMEWAndInitCodeCustom(address(mockValidator), abi.encodePacked(owner1), address(defaultExecutor), "", address(testHook), "", address(0), "");
        uint256 nonce = getNonceCustom(account, address(mockValidator));

        PackedUserOperation memory userOp = getDefaultUserOp();
        userOp.sender = address(account);
        userOp.nonce = nonce;
        userOp.initCode = initCode;
        userOp.callData = "aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd";

        bytes32 hash = entrypoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            owner1Key,
            ECDSA.toEthSignedMessageHash(hash)
        );
        bytes memory signature = abi.encodePacked(r, s, v);

        userOp.signature = signature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entrypoint.handleOps(userOps, payable(address(0x11421)));

        Execution[] memory batchCalls = new Execution[](2);
        batchCalls[0].target = address(account);
        batchCalls[0].value = 0;
        batchCalls[0].callData = abi.encodeWithSelector(ModularEtherspotWallet.uninstallModule.selector, uint256(1), address(mockValidator), "");

        batchCalls[1].target = address(account);
        batchCalls[1].value = 0;
        batchCalls[1].callData = abi.encodeWithSelector(ModularEtherspotWallet.uninstallModule.selector, uint256(1), address(mockValidator), "");

        defaultExecutor.execBatch(IERC7579Account(account), batchCalls);
    }
}
