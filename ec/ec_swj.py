#!/usr/bin/python3
#
# An elliptic curve in short Weierstrass form:
#
#   y^2 = x^3 + a * x + b
#
# Jacobian coordinates (X, Y, Z):
#
#   x = X / Z^2
#   y = Y / Z^3
#
# If Z = 0 then point at infinity (zero point)
#

import ec

from field import Fp

class Point (ec.Point):
	def __init__ (o, curve, x, y, z = 1):
		super  ().__init__ (curve, x, y)

		o.z = Fp (z, curve.p) if curve.p != 0 else z

	@property
	def X (o):
		o._scale ()
		return int (o.x)

	@property
	def Y (o):
		o._scale ()
		return int (o.y)

	def _scale (o):
		if o.z == 0 or o.z == 1:
			return

		a  = 1 / o.z
		aa = a * a

		(o.x, o.y, o.z) = (o.x * aa, o.y * aa * a, 1)

	def _dbl (a):
		(x3, y3, z3) = dbl (a.curve.a, a.x, a.y, a.z)

		return Point (a.curve, x3, y3, z3) if z3 != 0 else ec.Zero ()

	def _add (a, b):
		(x3, y3, z3) = add (a.x, a.y, a.z, b.x, b.y, b.z)

		if z3 == 0 and x3 == 0:  # and y3 == 0
			return _dbl (a)

		return Point (a.curve, x3, y3, z3) if z3 != 0 else ec.Zero ()

class SecurePoint (Point, ec.SecurePoint):
	def _dbl (o):
		(x3, y3, z3) = dbl_2007_bl (o.curve.a, o.x, o.y, o.z)

		return SecurePoint (o.curve, x3, y3, z3) if z3 != 0 else ec.Zero ()

	def _add (o, b):
		(x3, y3, z3) = add_2007_bl (o.x, o.y, o.z, b.x, b.y, b.z)

		if z3 == 0 and x3 == 0:  # and y3 == 0
			return o._dbl ()

		return SecurePoint (o.curve, x3, y3, z3) if z3 != 0 else ec.Zero ()

#
# Assumptions: z1 = 1 and z2 = 1
# Cost: 4M + 2S + 6add + 4*2 + 1*4
# Source: 2007 Bernstein–Lange
#
def mmadd_2007_bl (x1, y1, x2, y2):
	h  = x2 - x1
	i  = 4 * h ** 2
	j  = h * i
	r  = 2 * (y2 - y1)
	v  = x1 * i
	x3 = r ** 2 - j - 2 * v
	y3 = r * (v - x3) - 2 * y1 * j
	z3 = 2 * h

	return (x3, y3, z3)

#
# Assumptions: z1 = z2
# Cost: 5M + 2S + 9add
# Source: 2007 Meloni "New point addition formulae for ECC applications", p 192
#
def zadd_2007_m (x1, y1, z1, x2, y2):
	A  = (x2 - x1) ** 2
	B  = x1 * A
	C  = x2 * A
	dy = y2 - y1
	D  = dy ** 2
	x3 = D - B - C
	y3 = dy * (B - x3) - y1 * (C - B)
	z3 = z1 * (x2 - x1)

	return (x3, y3, z3)

#
# Assumptions: z2 = 1
# Cost: 7M + 4S + 9add + 3*2 + 1*4
# Source: 2007 Bernstein–Lange
#
def madd_2007_bl (x1, y1, z1, x2, y2):
	z1z1 = z1 ** 2
	u2 = x2 * z1z1
	s2 = y2 * z1 * z1z1
	h  = u2 - x1
	hh = h ** 2
	i  = 4 * hh
	j  = h * i
	r  = 2 * (s2 - y1)
	v  = x1 * i
	x3 = r ** 2 - j - 2 * v
	y3 = r * (v - x3) - 2 * y1 * j
	z3 = (z1 + h) ** 2 - z1z1 - hh

	return (x3, y3, z3)

#
# Cost: 11M + 5S + 9add + 4*2
# Cost: 10M + 4S + 9add + 4*2 dependent upon the first point
# Source: 2007 Bernstein–Lange
#
def add_2007_bl (x1, y1, z1, x2, y2, z2):
	z1z1 = z1 ** 2
	z2z2 = z2 ** 2
	u1 = x1 * z2z2
	u2 = x2 * z1z1
	s1 = y1 * z2 * z2z2
	s2 = y2 * z1 * z1z1
	h  = u2 - u1
	i  = (2 * h) ** 2
	j  = h * i
	r  = 2 * (s2 - s1)
	v  = u1 * i
	x3 = r ** 2 - j - 2 * v
	y3 = r * (v - x3) - 2 * s1 * j
	z3 = ((z1 + z2) ** 2 - z1z1 - z2z2) * h

	return (x3, y3, z3)

#
# Cost: 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8
# Source: 2007 Bernstein–Lange
#
def dbl_2007_bl (a, x1, y1, z1):
	xx = x1 ** 2
	yy = y1 ** 2
	yyyy = yy ** 2
	zz = z1 ** 2
	s  = 2 * ((x1 + yy) ** 2 - xx - yyyy)
	m  = 3 * xx + a * zz ** 2
	t  = m ** 2 - 2 * s
	x3 = t
	y3 = m * (s - t) - 8 * yyyy
	z3 = (y1 + z1) ** 2 - yy - zz

	return (x3, y3, z3)

#
# Assumptions: z1 = 1
# Cost: 1M + 5S + 7add + 3*2 + 1*3 + 1*8
# Source: 2007 Bernstein–Lange
#
def mdbl_2007_bl (a, x1, y1):
	xx = x1 ** 2
	yy = y1 ** 2
	yyyy = yy ** 2
	s  = 2 * ((x1 + yy) ** 2 - xx - yyyy)
	m  = 3 * xx + a
	t  = m ** 2 - 2 * s
	x3 = t
	y3 = m * (s - t) - 8 * yyyy
	z3 = 2 * y1

	return (x3, y3, z3)

#
# Entry functions
#
def add (x1, y1, z1, x2, y2, z2):
	if z2 == 1:
		if z1 == 1:
			return mmadd_2007_bl (x1, y1, x2, y2)

		return madd_2007_bl (x1, y1, z1, x2, y2)

	if z1 == z2:
		return zadd_2007_m (x1, y1, z1, x2, y2)

	return add_2007_bl (x1, y1, z1, x2, y2, z2)

def dbl (a, x1, y1, z1):
	if z1 == 1:
		return mdbl_2007_bl (a, x1, y1)

	return dbl_2007_bl (a, x1, y1, z1)
