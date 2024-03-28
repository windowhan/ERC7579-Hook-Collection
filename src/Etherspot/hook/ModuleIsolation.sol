// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ModularEtherspotWallet} from "etherspot-prime-contracts/src/modular-etherspot-wallet/wallet/ModularEtherspotWallet.sol";

import "etherspot-prime-contracts/src/modular-etherspot-wallet/erc7579-ref-impl/libs/ModeLib.sol";
import "etherspot-prime-contracts/src/modular-etherspot-wallet/erc7579-ref-impl/libs/ExecutionLib.sol";

import "erc7579-implementation/interfaces/IERC7579Module.sol";

import "forge-std/console.sol";

contract ModuleIsolationHook is IHook {
    using ModeLib for ModeCode;
    using ExecutionLib for bytes;

    mapping(address=>bool) public installed;

    function onInstall(bytes calldata data) external override {
        console.log("msg.sender : %s", msg.sender);
        installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata data) external override {
        installed[msg.sender] = false;
    }

    function contains(bytes4 target, bytes4[] memory list) public view returns (bool) {
        for(uint i=0;i<list.length;i++) {
            if(target==list[i])
                return true;
        }
        return false;
    }

    function preCheck(address msgSender, bytes calldata msgData) external override returns (bytes memory hookData){
        bytes4 firstFuncSig = bytes4(msgData[0:4]);
        if(firstFuncSig == ModularEtherspotWallet.executeFromExecutor.selector) {
            ModeCode mode = ModeCode.wrap(bytes32(msgData[4:36]));
            (CallType callType, ExecType execType, , ) = mode.decode();
            this.integrityCheck(callType, msgData[68+32:]);
        }
        return "";
    }

    function integrityCheck(CallType callType, bytes calldata executionCallData) public {
        bytes4[] memory bannedSigs = new bytes4[](5);
        bannedSigs[0] = ModularEtherspotWallet.execute.selector;
        bannedSigs[1] = ModularEtherspotWallet.executeFromExecutor.selector;
        bannedSigs[2] = ModularEtherspotWallet.executeUserOp.selector;
        bannedSigs[3] = ModularEtherspotWallet.installModule.selector;
        bannedSigs[4] = ModularEtherspotWallet.uninstallModule.selector;

        if (callType == CALLTYPE_BATCH) {
            Execution[] calldata executions = executionCallData.decodeBatch();
            for(uint i=0;i<executions.length;i++)
            {
                bytes4 checkSig = bytes4(executions[i].callData[0]) | (bytes4(executions[i].callData[1]) >> 8) | (bytes4(executions[i].callData[2]) >> 16) | (bytes4(executions[i].callData[3]) >> 24);
                require(!this.contains(checkSig, bannedSigs), "bannedSig..!");
            }

        } else if (callType == CALLTYPE_SINGLE) {
            (
                address target,
                uint256 value,
                bytes calldata callData
            ) = executionCallData.decodeSingle();

            bytes4 checkSig = bytes4(callData[0]) | (bytes4(callData[1]) >> 8) | (bytes4(callData[2]) >> 16) | (bytes4(callData[3]) >> 24);
            require(!this.contains(checkSig, bannedSigs), "bannedSig..!");

        } else if (callType == CALLTYPE_DELEGATECALL) {
            bytes4 checkSig = bytes4(executionCallData[0]) | (bytes4(executionCallData[1]) >> 8) | (bytes4(executionCallData[2]) >> 16) | (bytes4(executionCallData[3]) >> 24);
            require(!this.contains(checkSig, bannedSigs), "bannedSig..!");
        }
    }

    function postCheck(bytes calldata hookData) external returns (bool success){}

    function isModuleType(uint256 typeID) external view override returns (bool) {
        return MODULE_TYPE_HOOK==typeID;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return installed[smartAccount];
    }
}
