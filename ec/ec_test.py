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

o = ecgost.group ('ecgost-test-a')

d  = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28

e  = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
k  = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3

def test (name, d, P):
	start = time.clock ()

	for i in range (count):
		Q = d * P

	delta = (time.clock () - start) / count * 1000

	print ('{}: {:.2f} ms'.format (name, delta))

for i in range (rounds):
	P = ec.Point (o.curve, o.x, o.y)
	test ('swa    ', d, P)

	P = ec.SecurePoint (o.curve, o.x, o.y)
	test ('swa-sec', d, P)

	P = ec_swj.Point (o.curve, o.x, o.y)
	test ('swj    ', d, P)

	P = ec_swj.SecurePoint (o.curve, o.x, o.y)
	test ('swj-sec', d, P)

	print ()

# GOST R 34.10-2012

if test_ecgost:
	ecgost.test ()

if test_swj:
	P = ec_swj.SecurePoint (o.curve, o.x, o.y)
	Q = d * P
	C = k * P

	print ('P =', P)
	print ('qP =', o.q * P)
	print ('Q = dP =', Q)
	print ('C = kP =', C)
