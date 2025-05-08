---
title: "Crypto - Quantum Detanglement – UVT CTF 2025"
date: "2025-05-08"
excerpt: "Writeup of the crypto challenge Quantum Detanglement from UVT CTF 2025"
tags: ["crypto", "quantum"]
---

## Overview

Alice and Bob share a zero-noise quantum link and repeatedly prepare Bell pairs. Bob encodes a secret message by applying Pauli operators to his half of each pair (super-dense coding), and the server prints the resulting 2-qubit state vectors without collapsing them. Our goal is to reconstruct Bob’s classical message—the flag—by analyzing the printed stream of state vectors.

## 1. Challenge Description

- The server prints hundreds of lines, each like:
    Initial state = `Matrix([[sqrt(2)/2], [0], [0], [-sqrt(2)/2]])`
  
    `Matrix([[0], [-sqrt(2)/2], [sqrt(2)/2], [0]])`
  
    …

- Each `Matrix([[a0], [a1], [a2], [a3]])` represents a 2-qubit pure state

$$
\ket\psi = a_0\ket{00} + a_1\ket{01} + a_2\ket{10} + a_3\ket{11}\
$$

---

## 2. Bell States

There are four maximally entangled Bell basis states:

$$
\begin{aligned} \Phi^+ &= \frac{1}{\sqrt2}(\ket{00} + \ket{11}) & \Phi^- &= \frac{1}{\sqrt2}(\ket{00} - \ket{11})\\ \Psi^+ &= \frac{1}{\sqrt2}(\ket{01} + \ket{10}) & \Psi^- &= \frac{1}{\sqrt2}(\ket{01} - \ket{10}) \end{aligned}
$$

Each printed vector has coefficients only in ${0,\pm\sqrt2/2}$, so up to a global sign it must be one of these four.

**Note on global phase**: Multiplying a quantum state by $-1$ does not change any measurement outcome, e.g.

$$
-\Phi^+ = - \frac{\ket{00}+\ket{11}}{\sqrt2}
$$

is physically the same as $\Phi^+$. Thus the server’s "eight" variants collapse to four canonical labels.

---

## 3. Super-Dense Coding

Bob encodes two classical bits $(b_1,b_0)$ by applying a Pauli operator $P$ on his qubit:

|Bits $(b_1,b_0)$|Operator $P$|Resulting Bell state|
|---|---|---|
|(0,0)|$I$|$\Phi^+$|
|(0,1)|$X$|$\Psi^+$|
|(1,0)|$Z$|$\Phi^-$|
|(1,1)|$Y$|$\Psi^-$|

Alice prints the Bell state **after** Bob’s operation, allowing us to deduce which $P$ was applied.

## 4. Key Idea: Transitions

Instead of mapping each state directly to two bits (which would require guessing one of 24 possible label→bits maps), we look at **pairs** of successive Bell labels:

$$
\beta_{\text{prev}}\xrightarrow{P}\ \beta_{\text{cur}}
$$

For each $(\beta_{\text{prev}},\beta_{\text{cur}})$ there is exactly one $P\in{I,X,Z,Y}$. We then translate $P\to$ its two‐bit code according to the super-dense table.

Transition table:

|prev $\downarrow$ cur →|$\Phi^+$|$\Psi^+$|$\Phi^-$|$\Psi^-$|
|---|---|---|---|---|
|**$\Phi^+$**|I|X|Z|Y|
|**$\Psi^+$**|X|I|Y|Z|
|**$\Phi^-$**|Z|Y|I|X|
|**$\Psi^-$**|Y|Z|X|I|

Map operators to bits:  

$$
I\to00,\quad X\to01,\quad Z\to10,\quad Y\to11
$$

Concatenate all 2-bit chunks in order.

## 5. Step-by-Step Solve

1. **Download** the entire server output (a few KB).
2. **Parse** each line with a regex to extract four entries $a_0,a_1,a_2,a_3$.  
    Convert `$[sqrt(2)/2]` → $+1$, `-sqrt(2)/2` → $-1$, `[0]` → $0$.

3. **Classify** vector $v=[a_0,a_1,a_2,a_3]$:
    - If indices ${0,3}$ are non-zero ⇒ $\Phi$, else ${1,2}$ ⇒ $\Psi$.
    - Sign of product of those two entries decides “+” vs “−”.  

4. **Compute transitions**: for each consecutive pair of labels, look up $P$.
5. **Translate** each $P$ to two bits, build a long bit string.
6. **Trim** to a multiple of 8 bits, split into bytes, interpret as ASCII.
7. **Extract** the flag

## 6. Solve

```python
from pwn import remote
import math, re, string

HOST, PORT = "91.99.1.179", 60004
SQRT2_HALF = math.sqrt(2) / 2 # ~0.7071

r = remote(HOST, PORT)
data = r.recvall(timeout=10).decode("ascii", errors="ignore")
r.close()
print(f"got {len(data):,} bytes from server")

# turn each line into a 4 amplitude vector
def vec_from(line: str):
    m = re.search(r"\[\[(.*?)\]\]", line)
    if not m: return None
    parts = [p.replace('[','').replace(']','').strip()
             for p in m.group(1).split("],")]
    if len(parts) != 4: return None
    v = []
    for p in parts:
        if p.startswith("-sqrt"): v.append(-SQRT2_HALF)
        elif p.startswith("sqrt"): v.append( SQRT2_HALF)
        else: v.append(0.0)
    return v

vectors = [v for v in (vec_from(l) for l in data.splitlines()) if v]
print(f"parsed {len(vectors)} vectors")

# classify vector --> Bell state
def bell(v):
    # product of the two non zero amplitudes fixes the sign
    if v[0] or v[3]: # phi
        return "PHI+" if v[0]*v[3] > 0 else "PHI-"
    else: # psi
        return "PSI+" if v[1]*v[2] > 0 else "PSI-"

states = [bell(v) for v in vectors]

# transition table  (prev,cur) --> operator
T = {
  "PHI+": {"PHI+":'I',"PSI+":'X',"PHI-":'Z',"PSI-":'Y'},
  "PHI-": {"PHI-":'I',"PSI-":'X',"PHI+":'Z',"PSI+":'Y'},
  "PSI+": {"PSI+":'I',"PHI+":'X',"PSI-":'Z',"PHI-":'Y'},
  "PSI-": {"PSI-":'I',"PHI-":'X',"PSI+":'Z',"PHI+":'Y'},
}
P2B = {"I":"00", "X":"01", "Z":"10", "Y":"11"}

bits = ""
for a, b in zip(states, states[1:]):
    bits += P2B[T[a][b]]

print(f"extracted {len(bits)//2} operators ({len(bits)} bits)")

bits = bits[: len(bits)//8*8] # byte aligned
text = "".join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8))

print(text)
```

## 7. Why It Works

- **Global phase** ignored: ±1 doesn’t change Bell type.
- **Transitions** give the Pauli operator directly, no brute-force over label → bits.
- Standard **super-dense coding** mapping recovers the original 2-bit message sequence.

This method is robust to duplicate lines (removing duplicates optional) and prints, in order, exactly the bits Bob intended to send.

Much love 💋
