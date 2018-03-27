/*

  Copyright 2018 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.4.21;
pragma experimental ABIEncoderV2;

import "./LibOrder.sol";

contract LibExchangeDecoder is LibOrder {

    function get4(bytes b, uint256 index)
        internal
        pure
        returns (bytes4 result)
    {
        require(b.length >= index + 32);

        // Arrays are prefixed by a 256 bit length parameter
        index += 32;

        // Read the bytes32 from array memory
        assembly {
            result := mload(add(b, index))
        }
        return result;
    }

    function getFunctionSelector(bytes data)
        internal
        pure
        returns (bytes4 result)
    {
        result = get4(data, 0);
        return result;
    }

    function getFillOrderArgs(bytes data)
        internal
        pure
        returns (
            Order memory order,
            uint256 takerTokenFillAmount,
            bytes memory signature
        )
    {
        uint256 sigLen;
        assembly {
            let start := add(data, 36)                       // skip length + function selector
            mstore(order, mload(start))                      // senderAddress
            mstore(add(order, 32), mload(add(start, 32)))    // makerAddress
            mstore(add(order, 64), mload(add(start, 64)))    // takerAddress
            mstore(add(order, 96), mload(add(start, 96)))    // makerTokenAddress
            mstore(add(order, 128), mload(add(start, 128)))  // takerTokenAddress
            mstore(add(order, 160), mload(add(start, 160)))  // feeRecipientAddress
            mstore(add(order, 192), mload(add(start, 192)))  // makerTokenAmount
            mstore(add(order, 224), mload(add(start, 224)))  // takerTokenAmount
            mstore(add(order, 256), mload(add(start, 256)))  // makerFeeAmount
            mstore(add(order, 288), mload(add(start, 288)))  // takerFeeAmount
            mstore(add(order, 320), mload(add(start, 320)))  // expirationTimeSeconds
            mstore(add(order, 352), mload(add(start, 352)))  // salt
            takerTokenFillAmount := mload(add(start, 384))

            // skip signature offset stored at 416
            sigLen := mload(add(start, 448))
        }
        signature = new bytes(sigLen);
        assembly {
            let sigStart := add(data, 484)
            for { let curr := 0 }
            lt(curr, add(sigLen, 32))  // add 32 to copy trailing bytes
            { curr := add(curr, 32) }
            { mstore(add(signature, curr), mload(add(sigStart, curr))) }
        }
        return (order, takerTokenFillAmount, signature);
    }
}