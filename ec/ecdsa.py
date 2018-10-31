#!/usr/bin/python3
#
# ANS X9.62 Elliptic Curve Digital Signature
#
# Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
#
# Standard: ANS X9.62-1998, ANS X9.62-2005, FIPS-186-4
# SPDX-License-Identifier: BSD-2-Clause
#

from random import randrange
from field  import Fp
from ec     import Point, Group

def calc_r (P, q, k):
	C = k * P
	return C.X % q

def calc_s (q, d, e, k, r):
	return int ((Fp(k, q) ** -1) * (e + d * r))

def sign (md, P, q, d):
	if not isinstance (P, Point):
		raise ValueError ('P is not an EC point')

	e = md % q  # oops, should be `get higher n bits of md'
	if e == 0:
		e = 1

	while True:
		k = randrange (q)  # Warninig: this can not conform to B.5
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

	e = md % q  # oops, should be `get higher n bits of md'
	if e == 0:
		e = 1

	c  = Fp (s, q) ** -1
	u1 = int (e * c)
	u2 = int (r * c)

	C = u1 * P + u2 * Q
	R = C.X % q

	return R == r

def group (name):
	if name == 'ecdsa-test-192-a' or name == 'P-192':
		a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
		b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
		p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
		x = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
		y = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
		q = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
		return Group (a, b, p, x, y, q)

	if name == 'P-224':
		a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
		b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
		p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
		x = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
		y = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
		q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
		return Group (a, b, p, x, y, q)

	if name == 'ecdsa-test-239-a':
		a = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC
		b = 0x6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A
		p = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF
		x = 0x0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF
		y = 0x7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE  # calculated
		q = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B
		return Group (a, b, p, x, y, q)

	if name == 'ecdsa-test-256-a' or name == 'P-256':
		a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
		b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
		p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
		x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
		y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
		q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
		return Group (a, b, p, x, y, q)

	if name == 'P-384':
		a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
		b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
		p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
		x = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
		y = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
		q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
		return Group (a, b, p, x, y, q)

	if name == 'P-521':
		a = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
		b = 0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
		p = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
		x = 0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
		y = 0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
		q = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
		return Group (a, b, p, x, y, q)

	raise KeyError ('group not found')

def test ():
	o = group ('ecdsa-test-192-a')
	P = Point (o.curve, o.x, o.y)
	d = 0x1A8D598FC15BF0FD89030B5CB1111AEB92AE8BAF5EA475FB
	Q = d * P
	e = 0xA9993E364706816ABA3E25717850C26C9CD0D89D  # e = SHA-1('abc')
	(r, s) = sign (e, P, o.q, d)
	print ('Q =', Q)
	print ('r =', r)
	print ('s =', s)
	print ('verify =', verify (e, P, o.q, Q, r, s))
	print ()

	o = group ('ecdsa-test-239-a')
	P = Point (o.curve, o.x, o.y)
	d = 0x7EF7C6FABEFFFDEA864206E80B0B08A9331ED93E698561B64CA0F7777F3D
	Q = d * P
	e = 0xA9993E364706816ABA3E25717850C26C9CD0D89D  # e = SHA-1('abc')
	(r, s) = sign (e, P, o.q, d)
	print ('Q =', Q)
	print ('r =', r)
	print ('s =', s)
	print ('verify =', verify (e, P, o.q, Q, r, s))
	print ()
