#!/usr/bin/python3

from random import randrange
from field  import Fp
from ec     import Point

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
