---
title: "Crypto – Perfection – UVT CTF 2025"
date: "2025-05-09"
excerpt: "Writeup of the OTP‐oracle challenge Perfection from UVT CTF 2025"
tags: ["crypto", "linear", "algebra", "prng"]
---

## Overview

In **Perfection**, the server claims to implement a perfect **one‑time pad**, but in reality it reuses a fixed Pseudo‑Random Number Generator (PRNG) stream. We observe:

1. A single ciphertext of the flag (which we know starts with `UVT{…}`)
2. An interactive oracle: anything we send is XOR’d with the **same** PRNG output that encrypted the flag

By exploiting the **linearity** of the PRNG over $\mathrm{GF}(2)$, we collect exactly as many bits of keystream as the PRNG’s 800‑bit internal state, solve a giant linear system, recover the full state, and instantly decrypt the flag.


---


## 1. Challenge Description

When you connect:

```
$ nc 91.99.1.179 60006
I built a one-time pad oracle! :)
It's perfect! Nobody can decrypt anything without knowing the numbers.
Encrypted secret:
cf925ec4f280960cabb7ed4248500658b0eaf42585b4045e

Enter hex string:
```

- The **first** $L = \lceil|\text{flag}|/4\rceil$ PRNG outputs were XOR’d with the flag
- The server **continues** the same PRNG state for all subsequent inputs
- On each `Enter hex string:` prompt, anything you send is XOR’d with the **next** outputs of the PRNG

**Goal**: Recover `UVT{…}` without knowing the seed


---


## 2. PRNG Architecture

The C source defines a PRNG with a 25 × 32-bit (800‑bit) state vector $S$, updated as follows:

1.  **Twist & merge**:

$$
x = (s_k \mathbin{\&} \operatorname{UMASK}) \mathbin{|} (s_{k-(n-1)} \mathbin{\&} \operatorname{LMASK}), \quad xA = x\gg1 \oplus \begin{cases}a,& x \mathbin{\&} 1=1\\0,& x \mathbin{\&} 1=0\end{cases}
$$


2.  **Feedback**:

$$
x' = s_{k-(n-m)} \oplus xA,\quad s_k \leftarrow x',\quad k \leftarrow (k+1)\bmod n
$$


3.  **Tempering** (like MT):

$$
y = x'\oplus(x'\gg u),\quad y \leftarrow y \oplus ((y\ll s) \mathbin{\&} b), \quad y \leftarrow y \oplus ((y\ll t) \mathbin{\&} c), \quad z = y\oplus(y\gg l)
$$

All operations (XOR, bit‑shifts, AND‑masks) are **linear** over $GF(2)$


Constants:

| Parameter | Value         |
| :-------: | :------------ |
|    $n$    | 25            |
|    $m$    | 7             |
|    $w$    | 32            |
|    $r$    | 31            |
|    $a$    | 0x8EBFD028    |
| $u,s,t,l$ | 11, 7, 15, 18 |
|    $b$    | 0x2B5B2500    |
|    $c$    | 0xDB8B0000    |


---


## 3. OTP Reuse Flaw

A **true** OTP requires a fresh, random pad for each message. Here:

- The **flag** consumes PRNG outputs $z0,\dots,z{L-1}$
- The server **does not** reseed; it simply continues generating $zL,zL+1,…$
- By sending 100 zero‑bytes (`00…00`), we obtain $zL$ through $zL+24$, i.e. **25** outputs of 32 bits = **800 bits**.

Since the PRNG’s internal state is exactly **800 bits**, observing **800** consecutive output bits fully determines the state.


---


## 4. Linear State-Recovery Attack

Let:

- $\mathbf{S}\in\mathrm{GF}(2)^{800}$ be the unknown internal state **after** flag encryption.
- We observe $25$ outputs $zL,…,zL+24$, each 32 bits, giving $\mathbf{Z}\in\mathrm{GF}(2)^{800}$

Because each output bit is a linear function of $\mathbf{S}$, we construct:

$$
M\,\mathbf{S} = \mathbf{Z}, \quad M\in\mathrm{GF}(2)^{800\times800}
$$

- **Column** $i$ of $M$: initialize the PRNG state to the unit vector $e_i$ simulate 25 steps, collect 800 bits.
- **Solve** $\mathbf{S}=M^{-1}\mathbf{Z}$ in $\mathrm{GF}(2)$

This recovers the **exact** 800‑bit state in one shot.


---


## 5. Matrix Construction & GF(2) Algebra

```python
from sage.all import GF, Matrix

def build_matrix(start_idx):
    # build the 800×800 binary matrix over GF(2)
    F2 = GF(2)
    M  = Matrix(F2, 800, 800)
    for bit in range(800):
        # initialize state: single 1-bit at position `bit`
        arr = [0]*n
        arr[bit // 32] = 1 << (bit % 32)
        state = [arr[:], start_idx]
        col = []
        # simulate 25 PRNG outputs
        for _ in range(n):
            v = next_rand(state)
            # extract 32 bits LSB → MSB
            col += [(v >> b) & 1 for b in range(32)]
        # fill matrix column
        for i, b in enumerate(col):
            M[i, bit] = b
    return M
```

> **Performance**: ~4 s to build the matrix, ~1 s to solve a dense 800×800 system on a simple laptop.


---


## 6. Full Python/Sage Implementation

```python
from pwn import remote
import struct, re, time
from sage.all import GF, Matrix, vector

HOST, PORT = "91.99.1.179", 60006

n, m, w, r = 25, 7, 32, 31
UMASK = (0xffffffff << r) & 0xffffffff
LMASK = (0xffffffff >> (w - r)) & 0xffffffff
A_COEF = 0x8EBFD028
u, s, t, l = 11, 7, 15, 18
Bmask, Cmask = 0x2B5B2500, 0xDB8B0000

# twist + merge + temper --> next 32-bit PRNG output
def next_rand(state):
    arr, idx = state
    # twist/merge step
    x = (arr[idx] & UMASK) | (arr[(idx - (n-1)) % n] & LMASK)
    xA = (x >> 1) ^ (A_COEF if x & 1 else 0)
    x  = arr[(idx - (n-m)) % n] ^ xA
    arr[idx] = x
    state[1] = (idx + 1) % n
    # tempering step
    y = x ^ (x >> u)
    y ^= (y << s) & Bmask
    y ^= (y << t) & Cmask
    return (y ^ (y >> l)) & 0xffffffff

# apply only the temper function to invert/effect keystream
def temper(x):
    y = x ^ (x >> u)
    y ^= (y << s) & Bmask
    y ^= (y << t) & Cmask
    return (y ^ (y >> l)) & 0xffffffff

# build the 800×800 binary matrix over GF(2)
def build_matrix(start_idx):
    print("building 800×800 matrix (GF(2))")
    F2 = GF(2)
    M  = Matrix(F2, 800, 800)
    for bit in range(800):
        # initialize state
        arr = [0]*n
        arr[bit // 32] = 1 << (bit % 32)
        state = [arr[:], start_idx]
        col = []
        for _ in range(n):  # 25 outputs
            v = next_rand(state)
            # extract 32 bits LSB --> MSB
            col += [(v >> b) & 1 for b in range(32)]
        for i, b in enumerate(col):
            M[i, bit] = b
    return M

print("connecting to server…")
r = remote(HOST, PORT)
banner = r.recvuntil("Enter hex string: ")
print(f"received {len(banner)} bytes of banner")

# extract the ciphertext hex from banner
ct_hex = re.search(r'([0-9A-Fa-f]{32,})', banner.decode()).group(1)
print("ciphertext:", ct_hex)
ct = bytes.fromhex(ct_hex)
L = (len(ct) + 3)//4
print(f"{L} PRNG words were used to encrypt the flag")

print("requesting 25 PRNG outputs (keystream)")
r.send(b'00'*100 + b'\n')  # send 100 zero bytes

# receive until we find exactly 200 hex chars (25×8)
data = r.recvrepeat(timeout=2).decode()
ks_hex = re.search(r'([0-9A-Fa-f]{200})', data).group(1)
print("keystream received")
r.close()

# parse into 25 uint32 big-endian words
ks = [struct.unpack('>I', bytes.fromhex(ks_hex)[i:i+4])[0]
      for i in range(0, 100, 4)]

# reconstruct PRNG internal state
M = build_matrix(L % n)
print("solving linear system (800×800)")
rhs = vector(GF(2), [(w >> b) & 1 for w in ks for b in range(32)])
state_bits = M.solve_right(rhs)
print("internal state recovered")

# pack bits into 25 state words
state_words = [0]*n
for i, bit in enumerate(state_bits):
    if int(bit):
        state_words[i//32] |= 1 << (i % 32)

# regenerate keystream for flag and decrypt
print("decrypting flag")
stream = b''.join(struct.pack('>I', temper(state_words[i])) for i in range(L))
flag = bytes(a ^ b for a, b in zip(ct, stream[:len(ct)]))
print(flag.decode())
```


---


## 7. Step-by-Step Execution

1. **Connect** to the server and read the intro + ciphertext
2. **Parse** the ciphertext $hex \rightarrow c$. Compute $L=\lceil|c|/4\rceil$
3. **Send** `00…00` (100 bytes) $\rightarrow$ receive 25 PRNG outputs $\rightarrow$ parse 200 hex chars $\rightarrow$ $k_0,…,k_{24}$
4. **Construct** the 800×800 matrix by simulating each basis state through 25 PRNG steps
5. **Solve** the $GF(2)$ system to recover the 800‑bit state vector $S$
6. **Re‑temper** the first $L$ words of $S$ to reconstruct the keystream used on the flag
7. **XOR** with $c$ $\rightarrow$ flag

---

## 8. Why It Works

- **Linearity**: All PRNG operations are linear over $GF(2)$
- **Exact state size**: 25×32=800 bits
- **Sufficient output**: 25 outputs × 32 bits = 800 bits $\rightarrow$ full rank
- **Single inversion**: One 800×800 solve recovers the state


Much love 💋

Ap4sh
