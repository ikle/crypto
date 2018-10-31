#!/usr/bin/python3
#
# GOST Elliptic Curve Digital Signature
#
# Copyright (c) 2016-2018 Alexei A. Smekalkine <ikle@ikle.ru>
#
# Standard: GOST R 34.10-2012
# SPDX-License-Identifier: BSD-2-Clause
#

from random import randrange
from field  import Fp
from ec     import Point, Group

def calc_r (P, q, k):
	C = k * P
	return C.X % q

def calc_s (q, d, e, k, r):
	return (r * d + k * e) % q

def sign (md, P, q, d):
	if not isinstance (P, Point):
		raise ValueError ('P is not an EC point')

	e = md % q
	if e == 0:
		e = 1

	while True:
		k = randrange (q)
		r = calc_r (P, q, k)
		if r == 0:
			continue

		s = calc_s (q, d, e, k, r)
		if s != 0:
			break

	return (r, s)

def verify (md, P, q, Q, r, s):
	if not (isinstance (P, Point) and isinstance (Q, Point)):
		raise ValueError ('P or Q is not an EC point')

	e = md % q
	if e == 0:
		e = 1

	v  = Fp (e, q) ** -1
	z1 = int (s * v)
	z2 = int (-(r * v))

	C = z1 * P + z2 * Q
	R = C.X % q

	return R == r

def group (name):
	if name == 'ecgost-test-a':
		a = 0x7
		b = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
		p = 0x8000000000000000000000000000000000000000000000000000000000000431
		x = 0x2
		y = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8
		q = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
		return Group (a, b, p, x, y, q)

	if name == 'ecgost-test-b':
		a = 0x7
		b = 0x1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC
		p = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373
		x = 0x24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A
		y = 0x2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E
		q = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF
		return Group (a, b, p, x, y, q)

	raise KeyError ('group not found')

def test ():
	o = group ('ecgost-test-a')
	P = Point (o.curve, o.x, o.y)
	d = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
	Q = d * P
	e = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
	(r, s) = sign (e, P, o.q, d)
	print ('Q =', Q)
	print ('r =', r)
	print ('s =', s)
	print ('verify =', verify (e, P, o.q, Q, r, s))
	print ()

	o = group ('ecgost-test-b')
	P = Point (o.curve, o.x, o.y)
	d = 0xBA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4
	Q = d * P
	e = 0x3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C
	(r, s) = sign (e, P, o.q, d)
	print ('Q =', Q)
	print ('r =', r)
	print ('s =', s)
	print ('verify =', verify (e, P, o.q, Q, r, s))
	print ()
