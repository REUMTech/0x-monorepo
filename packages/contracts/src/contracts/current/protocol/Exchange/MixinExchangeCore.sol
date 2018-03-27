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
pragma experimental "v0.5.0";

import "./mixins/MExchangeCore.sol";
import "./mixins/MSettlement.sol";
import "./mixins/MSignatureValidator.sol";
import "./LibOrder.sol";
import "./LibErrors.sol";
import "./LibPartialAmount.sol";
import "./LibExchangeDecoder.sol";
import "../../utils/SafeMath/SafeMath.sol";

/// @dev Provides MExchangeCore
/// @dev Consumes MSettlement
/// @dev Consumes MSignatureValidator
contract MixinExchangeCore is
    LibOrder,
    MExchangeCore,
    MSettlement,
    MSignatureValidator,
    SafeMath,
    LibErrors,
    LibPartialAmount,
    LibExchangeDecoder
{
    // Mapping of transaction hash => executed
    mapping (bytes32 => bool) public transactions;

    // Mappings of orderHash => amounts of takerTokenAmount filled or cancelled.
    mapping (bytes32 => uint256) public filled;
    mapping (bytes32 => uint256) public cancelled;

    // Mapping of makerAddress => lowest salt an order can have in order to be fillable
    // Orders with a salt less than their maker's epoch are considered cancelled
    mapping (address => uint256) public makerEpoch;

    event Fill(
        address indexed makerAddress,
        address takerAddress,
        address indexed feeRecipientAddress,
        address makerTokenAddress,
        address takerTokenAddress,
        uint256 makerTokenFilledAmount,
        uint256 takerTokenFilledAmount,
        uint256 makerFeeAmountPaid,
        uint256 takerFeeAmountPaid,
        bytes32 indexed orderHash
    );

    event Cancel(
        address indexed makerAddress,
        address indexed feeRecipientAddress,
        address makerTokenAddress,
        address takerTokenAddress,
        uint256 makerTokenCancelledAmount,
        uint256 takerTokenCancelledAmount,
        bytes32 indexed orderHash
    );

    event CancelUpTo(
        address indexed maker,
        uint256 makerEpoch
    );

    /*
    * Core exchange functions
    */

    /// @dev Executes an exchange method call in the context of signer.
    /// @param salt Arbitrary number to ensure uniqueness of transaction hash.
    /// @param signer Address of transaction signer.
    /// @param data AbiV2 encoded calldata.
    /// @param signature Proof that transaction has been signed.
    function executeTransaction(
        uint256 salt,
        address signer,
        bytes data,
        bytes signature)
        external
    {
        // Calculate transaction hash
        bytes32 transactionHash = keccak256(salt, data);

        // Validate transaction has not been executed
        require(!transactions[transactionHash]);

        // Validate signature
        require(isValidSignature(transactionHash, signer, signature));

        // Execute transaction
        transactions[transactionHash] = true;
        if (getFunctionSelector(data) == this.fillOrder.selector) {
            Order memory order;
            uint256 takerTokenFillAmount;
            bytes memory makerSignature;
            (order, takerTokenFillAmount, makerSignature) = getFillOrderArgs(data);
            fillOrderInternal(signer, order, takerTokenFillAmount, makerSignature);
        }
    }

    /// @dev Fills the input order.
    /// @param order Order struct containing order specifications.
    /// @param takerTokenFillAmount Desired amount of takerToken to fill.
    /// @param signature Proof of signing order by maker.
    /// @return Total amount of takerToken filled in trade.
    function fillOrder(
        Order order,
        uint256 takerTokenFillAmount,
        bytes signature)
        public
        returns (uint256 takerTokenFilledAmount)
    {
       return fillOrderInternal(
           msg.sender,
           order,
           takerTokenFillAmount,
           signature
        );
    }

    /// @dev Cancels the input order.
    /// @param order Order struct containing order specifications.
    /// @param takerTokenCancelAmount Desired amount of takerToken to cancel in order.
    /// @return Amount of takerToken cancelled.
    function cancelOrder(
        Order order,
        uint256 takerTokenCancelAmount)
        public
        returns (uint256 takerTokenCancelledAmount)
    {
        return cancelOrderInternal(
            msg.sender,
            order,
            takerTokenCancelAmount
        );
    }

    /// @param salt Orders created with a salt less or equal to this value will be cancelled.
    function cancelOrdersUpTo(uint256 salt)
        external
    {
        uint256 newMakerEpoch = salt + 1;                // makerEpoch is initialized to 0, so to cancelUpTo we need salt+1
        require(newMakerEpoch > makerEpoch[msg.sender]); // epoch must be monotonically increasing
        makerEpoch[msg.sender] = newMakerEpoch;
        emit CancelUpTo(msg.sender, newMakerEpoch);
    }

    /// @dev Checks if rounding error > 0.1%.
    /// @param numerator Numerator.
    /// @param denominator Denominator.
    /// @param target Value to multiply with numerator/denominator.
    /// @return Rounding error is present.
    function isRoundingError(uint256 numerator, uint256 denominator, uint256 target)
        public pure
        returns (bool isError)
    {
        uint256 remainder = mulmod(target, numerator, denominator);
        if (remainder == 0) {
            return false; // No rounding error.
        }

        uint256 errPercentageTimes1000000 = safeDiv(
            safeMul(remainder, 1000000),
            safeMul(numerator, target)
        );
        isError = errPercentageTimes1000000 > 1000;
        return isError;
    }

    /// @dev Calculates the sum of values already filled and cancelled for a given order.
    /// @param orderHash The Keccak-256 hash of the given order.
    /// @return Sum of values already filled and cancelled.
    function getUnavailableTakerTokenAmount(bytes32 orderHash)
        public view
        returns (uint256 unavailableTakerTokenAmount)
    {
        unavailableTakerTokenAmount = safeAdd(filled[orderHash], cancelled[orderHash]);
        return unavailableTakerTokenAmount;
    }

    function fillOrderInternal(
        address takerAddress,
        Order memory order,
        uint256 takerTokenFillAmount,
        bytes memory signature)
        internal
        returns (uint256 takerTokenFilledAmount)
    {
        // Compute the order hash
        bytes32 orderHash = getOrderHash(order);

        // Validate order and maker only if first time seen
        // TODO: Read filled and cancelled only once
        if (filled[orderHash] == 0 && cancelled[orderHash] == 0) {
            require(order.makerTokenAmount > 0);
            require(order.takerTokenAmount > 0);
            require(isValidSignature(orderHash, order.makerAddress, signature));
        }
        
        // Validate sender
        if (order.senderAddress != address(0)) {
            require(order.senderAddress == msg.sender);
        }

        // Validate transaction signed by taker
        if (order.takerAddress != address(0)) {
            require(order.takerAddress == takerAddress);
        }
        require(takerTokenFillAmount > 0);

        // Validate order expiration
        if (block.timestamp >= order.expirationTimeSeconds) {
            emit ExchangeError(uint8(Errors.ORDER_EXPIRED), orderHash);
            return 0;
        }

        // Validate order availability
        uint256 remainingTakerTokenAmount = safeSub(order.takerTokenAmount, getUnavailableTakerTokenAmount(orderHash));
        takerTokenFilledAmount = min256(takerTokenFillAmount, remainingTakerTokenAmount);
        if (takerTokenFilledAmount == 0) {
            emit ExchangeError(uint8(Errors.ORDER_FULLY_FILLED_OR_CANCELLED), orderHash);
            return 0;
        }

        // Validate fill order rounding
        if (isRoundingError(takerTokenFilledAmount, order.takerTokenAmount, order.makerTokenAmount)) {
            emit ExchangeError(uint8(Errors.ROUNDING_ERROR_TOO_LARGE), orderHash);
            return 0;
        }

        // Validate order is not cancelled
        if (order.salt < makerEpoch[order.makerAddress]) {
            emit ExchangeError(uint8(Errors.ORDER_FULLY_FILLED_OR_CANCELLED), orderHash);
            return 0;
        }

        // Update state
        filled[orderHash] = safeAdd(filled[orderHash], takerTokenFilledAmount);

        // Settle order
        uint256 makerTokenFilledAmount;
        uint256 makerFeeAmountPaid;
        uint256 takerFeeAmountPaid;
        (makerTokenFilledAmount, makerFeeAmountPaid, takerFeeAmountPaid) =
            settleOrder(order, takerAddress, takerTokenFilledAmount);
        
        // Log order
        emit Fill(
            order.makerAddress,
            takerAddress,
            order.feeRecipientAddress,
            order.makerTokenAddress,
            order.takerTokenAddress,
            makerTokenFilledAmount,
            takerTokenFilledAmount,
            makerFeeAmountPaid,
            takerFeeAmountPaid,
            orderHash
        );
        return takerTokenFilledAmount;
    }

    function cancelOrderInternal(
        address makerAddress,
        Order order,
        uint256 takerTokenCancelAmount)
        internal
        returns (uint256 takerTokenCancelledAmount)
    {
        // Compute the order hash
        bytes32 orderHash = getOrderHash(order);

        // Validate the order
        require(order.makerTokenAmount > 0);
        require(order.takerTokenAmount > 0);
        require(takerTokenCancelAmount > 0);

        // Validate sender
        if (order.senderAddress != address(0)) {
            require(order.senderAddress == msg.sender);
        }
        
        // Validate transaction signed by maker
        require(order.makerAddress == makerAddress);
        
        if (block.timestamp >= order.expirationTimeSeconds) {
            emit ExchangeError(uint8(Errors.ORDER_EXPIRED), orderHash);
            return 0;
        }
        
        // Calculate amount to cancel
        uint256 remainingTakerTokenAmount = safeSub(order.takerTokenAmount, getUnavailableTakerTokenAmount(orderHash));
        takerTokenCancelledAmount = min256(takerTokenCancelAmount, remainingTakerTokenAmount);
        if (takerTokenCancelledAmount == 0) {
            emit ExchangeError(uint8(Errors.ORDER_FULLY_FILLED_OR_CANCELLED), orderHash);
            return 0;
        }
        
        // Update state
        cancelled[orderHash] = safeAdd(cancelled[orderHash], takerTokenCancelledAmount);
        
        // Log cancel
        emit Cancel(
            order.makerAddress,
            order.feeRecipientAddress,
            order.makerTokenAddress,
            order.takerTokenAddress,
            getPartialAmount(takerTokenCancelledAmount, order.takerTokenAmount, order.makerTokenAmount),
            takerTokenCancelledAmount,
            orderHash
        );
        return takerTokenCancelledAmount;
    }
}
