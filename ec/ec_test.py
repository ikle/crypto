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

test_egost = True
test_swj   = True

p  = 0x8000000000000000000000000000000000000000000000000000000000000431 
a  = 0x7
b  = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E 

m  = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
q  = m

Px = 0x2
Py = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8

d  = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
#Qx = 0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B
#Qy = 0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA

e  = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
k  = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3

#Cx = 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
#Cy = 0x489C375A9941A3049E33B34361DD204172AD98C3E5916DE27695D22A61FAE46E

# r = Cx (mod q)
#r  = 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
# s = rd + ke (mod q)
#s  = 0x1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40

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

if test_egost:
	P = ec.Point (curve, Px, Py)
	Q = d * P
	C = k * P
	r = C.X % q
	s = (r * d + k * e) % q

	print ('curve:', curve)
	print ()
	print ('P =', P)
	print ('qP =', q * P)
	print ('Q = dP =', Q)
	print ('C = kP =', C)
	print ()
	print ('r =', r)
	print ('s =', s)
	print ()

	v  = Fp (e, q) ** -1
	z1 = int (s * v)
	z2 = int (-(r * v))
	C = z1 * P + z2 * Q
	R = C.X % q

	print ('v  =', int (v))
	print ('z1 =', z1)
	print ('z2 =', z2)
	print ('C =', C)
	print ('R =', R)
	print ()

	(r, s) = ecgost.sign (e, P, q, d)
	print ('r =', r)
	print ('s =', s)
	print ('ecgost.verify =', ecgost.verify (e, P, q, Q, r, s))
	print ()

if test_swj:
	P = ec_swj.SecurePoint (curve, Px, Py)
	Q = d * P
	C = k * P

	print ('P =', P)
	print ('qP =', q * P)
	print ('Q = dP =', Q)
	print ('C = kP =', C)

