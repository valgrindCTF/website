---
title: "Hardware - Lost-in-Madras - bi0s CTF 2025"
date: "2025-06-09"
excerpt: "Or; Epic Fail by the Challenge Creator—They Got Their Own Flag DEAD WRONG and You Won't Believe Why"
tags: ["hw", "rev"]
---

## Overview

![challenge description](/static/img/posts/2025-bi0s-hw-madras/descr.webp)

Solves: 4

![solves](/static/img/posts/2025-bi0s-hw-madras/solves.webp)

Not a hard hardware challenge involving parsing CAN bus log tho many people find it confusing and struggle to get correct results so I decided to issue this writeup

---

## 1. Challenge Description

We presented 38Mbyte canlog.txt with contents like:

```plain
... snip ...
  vcan1  095   [8]  80 00 07 F4 00 00 00 17
  vcan1  1A4   [8]  00 00 00 08 00 00 00 10
  vcan1  423   [5]  10 27 00 00 00
  vcan1  1AA   [8]  7F FF 00 00 00 00 68 10
  vcan1  1B0   [7]  00 0F 00 00 00 01 57
  vcan1  1D0   [8]  00 00 00 00 00 00 00 0A
  vcan1  166   [4]  D0 32 00 27
  vcan1  158   [8]  00 00 00 00 00 00 00 28
  vcan1  161   [8]  00 00 05 50 01 08 00 2B
  vcan1  191   [7]  01 00 10 A1 41 00 1A
  vcan1  133   [5]  00 00 00 00 B6
  vcan1  136   [8]  00 02 00 00 00 00 00 39
  vcan1  13A   [8]  00 00 00 00 00 00 00 37
... snip ...
```

So we have some CAN bus communications log and need to extract meaningful data: VIN and (possible) GPS coordinates.

---

## 2. Obtaining VIN

This is my second time to mess with CAN communications, previous one was at the `Volnatek Motors` challenge from `HTB Business CTF 2025`, see [author's writeup](https://github.com/hackthebox/business-ctf-2025/tree/master/hardware/VolnatekMotors)

So at the moment being a bit familiar with UDS messages I immediately searched for `22 F1 90` which is commonly used to query VIN and got match:

```plain
  vcan0  733   [8]  03 22 F1 90 00 00 00 00
  vcan0  73B   [8]  10 14 62 F1 90 31 46 4D
```

I'm not going deep into UDS here, just note that this response's data length is 0x14 and its split across multiple packets. In order to get remaining data, sender (733) should issue SYNC packet and wait for remaining parts, here is the rest of vin query:

```plain
  vcan0  733   [8]  30 00 00 00 00 00 00 00
  ... snip ...
  vcan0  73B   [8]  21 48 4B 37 44 38 32 42
  vcan0  73B   [8]  22 47 41 33 34 39 35 34
```

Here is full data response to VIN request:

```hexdump
00000000  62 f1 90 31  46 4d 48 4b  37 44 38 32  42 47 41 33  |b··1FMHK7D82BGA3|
00000010  34 39 35 34                                         |4954|
```

`62` means we have successful reply to command `22` (Read Data by Identifier)

`f1 90` - is requested identifier reflected back

And we got first part of the flag 🎉

VIN: `1FMHK7D82BGA34954`

Lets [decode](https://vpic.nhtsa.dot.gov/decoder/Decoder?VIN=1FMHK7D82BGA34954&ModelYear=) this VIN to get more detailed info:

![vin decode](/static/img/posts/2025-bi0s-hw-madras/vin.webp)

---

## 3. Obtaining Vehicle Last Position

When I came to this challenge one of my team-mates (@Rev) already did some frequency analysis:

```plain
ID 095 has 8 unique values: ['800007F400000008', ...]
ID 1A4 has 4 unique values: ['0000000800000001', ...]
ID 423 has 592 unique values: ['0036000000', ...]
ID 1AA has 8 unique values: ['7FFF000000006702', ...]
ID 1B0 has 4 unique values: ['000F0000000148', ...]
ID 1D0 has 1 unique values: ['000000000000000A']
ID 166 has 4 unique values: ['D0320009', ...]
ID 158 has 4 unique values: ['000000000000000A', ...]
ID 161 has 4 unique values: ['000005500108000D', ...]
ID 191 has 8 unique values: ['010010A141000B', ...]
ID 133 has 4 unique values: ['0000000089', ..]
ID 136 has 4 unique values: ['000200000000000C', ...]
ID 13A has 4 unique values: ['000000000000000A', ...]
ID 13F has 4 unique values: ['0000000500000000', ...]
ID 164 has 8 unique values: ['0000C01AA8000004', ...]
ID 17C has 4 unique values: ['0000000010000003', ...]
ID 18E has 4 unique values: ['00004D', ...]
ID 294 has 4 unique values: ['040B0002CF5A000E', ...]
ID 21E has 4 unique values: ['03E83745220601', ...]
ID 309 has 4 unique values: ['0000000000000084', ...]
ID 039 has 4 unique values: ['000C', ...]
ID 183 has 64 unique values: ['0000000200001009', ...]
ID 143 has 4 unique values: ['6B6B00C2', ...]
ID 1CF has 4 unique values: ['80050000000F', ...]
ID 1DC has 4 unique values: ['0200000C', ...]
ID 305 has 4 unique values: ['8008', ...]
ID 333 has 4 unique values: ['0000000000000F', ...]
ID 320 has 4 unique values: ['000003', ...]
ID 324 has 4 unique values: ['7465000000000E0B', ...]
ID 37C has 4 unique values: ['FD00FD00097F000B', ...]
ID 5A1 has 3 unique values: ['9600000000006210', ...]
ID 40C has 4 unique values: ['0000000004000013', ...]
ID 454 has 4 unique values: ['23EF09', ...]
ID 428 has 4 unique values: ['01040000521C01', ...]
ID 405 has 4 unique values: ['000004000000000B', ...]
ID 188 has 3 unique values: ['00000000', ...]
ID 465 has 9 unique values: ['660DF4481A0EDD00', ...]
ID 733 has 14 unique values: ['0210030000000000', ...]
ID 73B has 17 unique values: ['0267160000000000', ...]
```

ID 465 looks incredibly packed with data, here is its values ordered by presence in the log file:

```unknown
66 16 1A 08 1A 2B AE 00
66 15 06 08 1A 29 20 00
66 14 4C 08 1A 21 8B 00
66 12 55 88 1A 11 EC 00
66 12 35 A8 1A 0A 00 00
66 11 8E 68 1A 0F E2 00
66 10 D2 28 1A 09 7F 00
66 10 32 C8 1A 06 82 00
66 0D F4 48 1A 0E DD 00
```

I tried to google `ford can id 465` and pretty soon found this image cached from some closed google group:

![id 465 reference](/static/img/posts/2025-bi0s-hw-madras/id-465.webp)

So its indeed packed GPS coordinates. As we need only last location of the vehicle I decided to parse last message by hand, its only 7 bytes long and zero byte:

`66 0D F4 48 1A 0E DD 00`

So we need to extract the following parts:

```unknown
8 bits for lat degrees
6 bits for lat minutes
14 bits for lat min fractions
9 bits for lon degrees
6 bits for lon minutes
14 bits for lon min fractions
```

57 bits total = 7 bytes + 1 bit

At this point I was stuck for a moment as I got coords pointing at the middle of the ocean 😵‍💫

---

So lets step back and reconsider

Challenge name hints us that destination coords should be somewhere near Madras, lets google it:

![madras](/static/img/posts/2025-bi0s-hw-madras/map.webp)

Its called Chennai here, but its just another name:

![chennai](/static/img/posts/2025-bi0s-hw-madras/name.webp)

So now we know that we are looking for (13 N, 80 E)

Lets pack it to see how it should look in the GPS log message. In order to do that we need to offset latiture by adding 89 and offset longitude by adding 179:

Lat Deg = 13 + 89 = 102 = 0x66

Lon Deg = 80 + 179 = 259 = 0x103

At this point we are ready to look into captured messages again:

```unknown
66 16 1A 08 1A 2B AE 00
66 15 06 08 1A 29 20 00
66 14 4C 08 1A 21 8B 00
66 12 55 88 1A 11 EC 00
66 12 35 A8 1A 0A 00 00
66 11 8E 68 1A 0F E2 00
66 10 D2 28 1A 09 7F 00
66 10 32 C8 1A 06 82 00
66 0D F4 48 1A 0E DD 00
```

I can spot Latitude (`66`) part but can't see Longitude part (`0x103`)

At this point I noticed something strage - column of `_8 1A` in the middle of the data. Why lowest nibble of the third byte is constant? Is it part of the Longitude value?

At this point I tried something strange:

```py
>>> hex(0x81A >> 3)
'0x103'
```

Seriously?

Lets check obvious assumption:

1. Convert coord line to binary byte by byte:

```plain
    Byte 0: 0x66 = 01100110
    Byte 1: 0x0d = 00001101
    Byte 2: 0xf4 = 11110100
    Byte 3: 0x48 = 01001000
    Byte 4: 0x1a = 00011010
    Byte 5: 0x0e = 00001110
    Byte 6: 0xdd = 11011101
    Byte 7: 0x00 = 00000000
```

2. Concatenate all binary values into one sting:

`0110011000001101111101000100100000011010000011101101110100000000`

3. Split into 8, 6, 14, 9, 6, 14 len blocks:

`01100110 000011 01111101000100 100000011 010000 01110110111010 0000000`

4. Convert each section into numeral:

`102 3 8004 259 16 7610`

5. Add offsets/scale as specified in table above:

```plain
Lat Deg = 102 - 89 = 13
Lat Min = 3
Lat MFr = 8004/10000 = 0.8004
Lon Deg = 259 - 179 = 80
Lon Min = 16
Lon MFr = 7610/10000 = 0.7610
```

6. Look up using google maps:

`13 3.8004' N 80 16.7610' E`

![found it](/static/img/posts/2025-bi0s-hw-madras/place.webp)

Checked it and yup, we have a flag!

## 4. Homework

Initially I thought that its a challenge author decision to encode GPS coords that way but eventually @Sylvie got posted this dbc snipped to bi0s ctf discord and it appears to be working:

```plain
BO_ 1125 GPS_Data_Nav_1: 8  XXX
 SG_ GPS_Longitude_Minutes        : 34|6@0+ (1,0)    [0|0] "Minutes" XXX
 SG_ GPS_Longitude_Min_dec        : 44|14@0+ (0.0001,0)[0|0] "Minutes" XXX
 SG_ GPS_Longitude_Degrees        : 27|9@0+ (1,-179.0)[0|0] "Degrees" XXX
 SG_ GPS_Latitude_Minutes         : 15|6@0+ (1,0)    [0|0] "Minutes" XXX
 SG_ GPS_Latitude_Min_dec         : 9|14@0+ (0.0001,0)[0|0] "Minutes" XXX
 SG_ GPS_Latitude_Degrees         : 7 |8@0+ (1,-89.0) [0|0] "Degrees" XXX
```

So I decided to dig deeper by starting reading how to read it [here](https://www.csselectronics.com/pages/can-dbc-file-database-intro) and [here](https://docs.openvehicles.com/en/latest/components/vehicle_dbc/docs/dbc-primer.html)

Here is the most interesting parts:

![dbc structure](/static/img/posts/2025-bi0s-hw-madras/dbc-basics.webp)
![bits](/static/img/posts/2025-bi0s-hw-madras/dbc-bits.webp)

---

Some points to take note:

- Start bit always found by interpreting value as little endian

- If value is big endian then start bit specifies end of the bit field

---

Using this information lets try to read DBC file:

1. GPS_Latitude_Degrees

Starts from bit 7, length 8 bits, big endian and unsigned (@0+), scale 1, offset -89

Its big endian so in order to extract it you should start from bit 7 and go down to bit 0, lets do it using image:
![lat deg](/static/img/posts/2025-bi0s-hw-madras/lat-deg.webp)

2. GPS_Latitude_Minutes

Starts from bit 15, length 6 bits, big endian and unsigned (@0+), scale 1, offset 0:
![lat min](/static/img/posts/2025-bi0s-hw-madras/lat-min.webp)

3. GPS_Latitude_Min_dec

Starts from bit 9, length 14 bits, big endian and unsigned (@0+), scale 0.0001, offset 0

This one is a bit tricky. Start from bit 9 and count down 14 bits

<img style="float: left;" src="/static/img/posts/2025-bi0s-hw-madras/subzero.gif">

Shouln't we go below bit zero here?

To solve this last piece of the puzzle just notice that we have **big endian** value, which means that most significant byte stored at the least memory address

Here is how 64 bit value represented in memory:

![bits](/static/img/posts/2025-bi0s-hw-madras/bits.webp)

See? We have highest bit on the left and lowest bit on the right and they are monotone decrement when you move from left to right

Source of confusion arises because **start** bit specified using little endian notation, here is it bit 9:

![bit9](/static/img/posts/2025-bi0s-hw-madras/bit9.webp)

But its actual bit **49** of **big endian** notation and you need to extract 14 bits downward from it:

![bit9bf](/static/img/posts/2025-bi0s-hw-madras/bit9bf.webp)

## 5. Things Learned / Conslusions

- Bit fields are fun
- Some reference materials may miss important details. Like that table describing 465 message completely misses to mention about little/big endian

--

BR, ed
