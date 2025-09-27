---

title: "Crypto - Shilla – Olympics CTF 2025"
date: "2025-09-27"
excerpt: "Writeup of Shilla, hyperelliptic-curve challenge from Olympics CTF 2025"
tags: ["crypto", "hyperelliptic"]
author: "Ap4sh"
---

---

## Overview

We are given seven elements of the Jacobian of a large **hyperelliptic** curve over $\mathbb F_p$. Each printed line is a Mumford pair $U(x),,y\pm V(x)$ equal to an unknown base class $X$ multiplied by

$k_t=t(t{+}1)(t{+}2),\quad t\in{5,\dots,11}$

like

$\mathcal K={210,336,504,720,990,1320,1716}$

Goal is to reconstruct the curve $y^2=f(x)$, isolate $6X$, read $u$ from $U_{6X}$, then compute $m=\pm\sqrt{f(u)}\in\mathbb F_p$. Converting $m$ to bytes yields the flag


---


## 1. Challenge description

* The server prints 7 lines, each like:

  `(<monic U(x)>, y + <V(x)>)`
  `(<monic U(x)>, y - <V(x)>)`
  …

* Each tuple represents a reduced divisor class in Mumford form $(U,V)$ on a hyperelliptic curve

$H:\ y^2=f(x)\qquad(\text{with }h(x)=0)$

* Genus is $g=63$, so $\deg f=2g+1=127$. The seven classes are $k\cdot X : k\in\mathcal K$ in unknown order

---

## 2. Mumford representation

For every printed pair $U(x),,y\pm V(x)$ we normalize to $U, y - V$ one always has

$$
V(x)^2 \equiv f(x)\pmod{U(x)},\qquad
\deg U \le g,\ \deg V < \deg U
$$

This congruence is the key to recoverv $f$


---


## 3. Reconstructing the curve f(x)

Write

$$
f(x)=\sum_{j=0}^{127} c_j x^j\in\mathbb F_p[x]
$$

For each sample $i$,

$$
V_i(x)^2 \equiv f(x)\pmod{U_i(x)}
$$

Reducing $x^j\bmod U_i$ provides $\deg U_i$ linear equations in ${c_j}$. Stacking all 7 samples yields a tall, consistent linear system over $\mathbb F_p$, uniquely determining $f$. 
We verify by checking

$$
(V_i^2 - f)\bmod U_i = 0\quad \text{for all }i
$$



---


## 4. Key idea: isolating 6X

Among the multipliers, several pairs have $\gcd=6$, like

$$
\gcd(210,1716)=\gcd(336,990)=6
$$

For two observed classes $P=k_aX$ and $Q=k_bX$, choose Bezout integers $s,t$ such that

$$
s,k_a + t,k_b = 6 \quad\Longrightarrow\quad S := sP + tQ = 6X
$$

Because we do not know which printed class corresponds to which $k$, we try **all** ordered pairs $P,Q$ and all $\gcd{=}6)$ pairs $(k_a,k_b)$, producing candidates $S$

The true $S=6X$ achieves full coverage we got $\text{score}=7$


---


## 5. Reading (u) from a small multiple

For small multiples $i\le g$ one has the simple shape

$$
U_{iX}(x)=(x-u)^i.
$$

In particular,

$$
U_{6X}(x)=(x-u)^6=x^6-6u,x^5+\cdots
\quad\Rightarrow\quad
u \equiv -\frac{[x^5],U_{6X}}{6}\pmod p
$$


---


## 6. Recovering m (and the flag)

Evaluate

$$
m=\pm\sqrt{f(u)}\in\mathbb F_p
$$

Exactly one sign makes ${k\cdot (u,m)}$ match **all** printed classes; that sign is the real $m$. Convert $m$ (big-endian) to bytes → the flag


---


## 7. Step by step solve

1. Parse the 7 Mumford pairs and the prime $p$
2. Solve the linear system for $f$ degree 127; verify $V_i^2\equiv f\bmod U_i$ for all $i$
3. Enumerate Bezout combinations across all printed pairs to get candidates $S=6X$; score each by coverage, keep the best
4. Extract $u$ from $U_{6X}=(x-u)^6$ via the coefficient of $x^5$
5. Compute $m=\pm\sqrt{f(u)}$ and pickk the sign that reproduces all seven samples
6. Decode $m$ as bytes to obtain the flag


---


## 8. Solve

```python
import sys, re
from sage.all import *

path = sys.argv[1]
raw  = open(path, 'r').read()
p    = Integer(re.search(r"p\s*=\s*([0-9]+)", raw).group(1))
tuples = re.findall(r"\(\s*[^()]*\)", raw)[:7]

# base ring
Fp = GF(p)
R.<x> = PolynomialRing(Fp)

# parse a Mumford "(U(x), y ± V(x))" into (U, V) with (U, y - V) convention
def parse_mumford(s):
    inside = s[1:-1].strip()
    i = inside.find(',')
    U = R(inside[:i].strip().replace('^','**'))
    m = re.match(r"y\s*([+-])\s*(.*)$", inside[i+1:].strip())
    W = R(m.group(2).strip().replace('^','**'))
    V = -W if m.group(1) == '+' else W
    if U.leading_coefficient() != 1:
        lc = U.leading_coefficient(); U = U/lc; V = V/lc
    return U, (V % U)

UVs = [parse_mumford(s) for s in tuples]

# reconstruct f(x) of degree 127 from V^2 ≡ f (mod U)
degF = 127
nunk = degF + 1
rows, rhs = [], []
for (U,V) in UVs:
    Qi = (V*V) % U
    d  = U.degree()
    rem = [R(0)]*nunk
    rem[0] = R(1) % U
    if nunk > 1:
        rem[1] = x % U
        for j in range(2, nunk):
            rem[j] = (rem[j-1]*x) % U
    for a in range(d):
        rows.append([ Fp(rem[j][a]) for j in range(nunk) ])
        rhs.append(Fp(Qi[a]))

A = matrix(Fp, rows)
b = vector(Fp, rhs)
c = A.solve_right(b) # consistent tall system
coeffs = list(c)
f = sum(R(coeffs[j])*x**j for j in range(nunk))

# build curve & the 7 Jacobian elements
H = HyperellipticCurve(f, 0)
J = H.jacobian()(Fp)
Pts = [ J([U,V]) for (U,V) in UVs ]

# find S = 6X by Bezout combos of pairs with gcd=6, keep the best coverage
Ks = [210,336,504,720,990,1320,1716]
pairs = []
for i in range(len(Ks)):
    for j in range(i+1,len(Ks)):
        if gcd(Integer(Ks[i]), Integer(Ks[j])) == 6:
            g,s,t = xgcd(Ks[i], Ks[j]); pairs.append((s,t))
            g,s,t = xgcd(Ks[j], Ks[i]); pairs.append((s,t))

cands = []
for a in range(len(Pts)):
    for b in range(len(Pts)):
        if a==b: continue
        for (s,t) in pairs:
            cands.append(s*Pts[a] + t*Pts[b])

ns = [k//6 for k in Ks]
bestS, bestScore = None, -1
for S in cands:
    imgs = [n*S for n in ns]
    sc = sum(1 for P in Pts if any(P==Y for Y in imgs))
    if sc > bestScore:
        bestScore, bestS = sc, S

# read u from U_{6X} = (x - u)^6
U6 = bestS[0]
xU = U6.parent().gen()
u  = Fp((-U6.monomial_coefficient(xU**5)) * inverse_mod(6, p))

# m = ±sqrt(f(u)); pick the sign that matches all 7 samples
val = Fp(f(u))
r   = val.sqrt()
cand = [r, -r]
good = cand[0]
for rr in cand:
    base = J(H((u, rr)))
    gens = [k*base for k in Ks]
    if all(any(P==G for G in gens) for P in Pts):
        good = rr
        break

m = int(good) % p
blen = (m.bit_length() + 7)//8
flag = int(m).to_bytes(blen, 'big').decode('utf-8', 'ignore')
print(flag)
```
---
```bash
➜ sage solve.sage Shilla/output.txt
ASIS{hYP3RcURc3S_4rE_w31rd_m4th_bU7_8r0k3n_4_s3cur1ty_n0T4W3aKs!}

took 11m 36.1s
```


---


## 9. Why it works

* Mumford congruence $V^2\equiv f \pmod U$ yields a linear system that pins down all (128) coefficients of $f$
* Bezout + $\gcd=6$ lets us synthesize $6X$ from two unlabeled multiples
* For $i\le g$, the small-multiple shape $U_{iX}(x)=(x-u)^i$ exposes $u$ via the coefficient of $x^{i-1}$
* The sign of $m=\pm\sqrt{f(u)}$ is fixed by requiring its multiples to match **all** printed samples


---


## 10. Sources i used to solve

https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/hyperelliptic_curves/jacobian_morphism.html

https://rkm0959.tistory.com/285

https://neuromancer.sk/article/25

https://www.ams.org/journals/mcom/1987-48-177/S0025-5718-1987-0866101-0/S0025-5718-1987-0866101-0.pdf


---

Much love 💋

Ap4sh
