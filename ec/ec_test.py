#!/usr/bin/python3
#
# Elliptic Curve test code
#
# Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
#
# SPDX-License-Identifier: BSD-2-Clause
#

import time
import ec, ec_swj, ecgost

from field import Fp

count = 100
rounds = 0

test_ecgost = True
test_swj    = True

p  = 0x8000000000000000000000000000000000000000000000000000000000000431 
a  = 0x7
b  = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E 

m  = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
q  = m

Px = 0x2
Py = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8

d  = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28

e  = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
k  = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3

curve = ec.Curve (a, b, p)

def test (name, d, P):
	start = time.clock ()

	for i in range (count):
		Q = d * P

	delta = (time.clock () - start) / count * 1000

	print ('{}: {:.2f} ms'.format (name, delta))

for i in range (rounds):
	P = ec.Point (curve, Px, Py)
	test ('swa    ', d, P)

	P = ec.SecurePoint (curve, Px, Py)
	test ('swa-sec', d, P)

	P = ec_swj.Point (curve, Px, Py)
	test ('swj    ', d, P)

	P = ec_swj.SecurePoint (curve, Px, Py)
	test ('swj-sec', d, P)

	print ()

# GOST R 34.10-2012

if test_ecgost:
	ecgost.test ()

if test_swj:
	P = ec_swj.SecurePoint (curve, Px, Py)
	Q = d * P
	C = k * P

	print ('P =', P)
	print ('qP =', q * P)
	print ('Q = dP =', Q)
	print ('C = kP =', C)

