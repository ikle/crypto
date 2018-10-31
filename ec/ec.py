#!/usr/bin/python3
#
# Elliptic Curve in short Weierstrass form in Affine coordinates
#
# Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
#
# SPDX-License-Identifier: BSD-2-Clause
#

from field import Fp

#
# Elliptic Curve in short Weierstrass form
#
class Curve (object):
	def __init__ (o, a, b, p = 0):
		o.a = a
		o.b = b
		o.p = p

	def __repr__ (o):
		eqn = 'y^2 = x^3 + {}x + {}'.format (o.a, o.b)
		return eqn if o.p == 0 else '{} (mod {})'.format (eqn, o.p)

#
# Zero point: point at infinity
#
class Zero (object):
	def __repr__ (o):
		return 'O'

	def __lshift__ (o, n):
		return Zero ()

	def __add__ (o, other):
		if isinstance (other, Zero):
			return o

		if isinstance (other, Point):
			return other

		return NotImplemented

#
# Curve Point
#
class Point (object):
	def __init__ (o, curve, x, y):
		if not isinstance (curve, Curve):
			raise ValueError ('curve expected')

		o.curve = curve
		o.x = Fp (x, curve.p) if curve.p != 0 else x
		o.y = Fp (y, curve.p) if curve.p != 0 else y

	def __repr__ (o):
		return '({}, {})'.format (o.X, o.Y)

	def __copy__ (o):
		return type (o) (o.curve, o.x, o.y)

	@property
	def X (o):
		return int (o.x)

	@property
	def Y (o):
		return int (o.y)

	def _dbl (o):
		(x, y) = swa_dbl (o.curve.a, o.x, o.y)

		return Point (o.curve, x, y)

	def __lshift__ (o, n):
		if not isinstance (n, int):
			raise ValueError ('shift count is not an integer')

		if n < 1:
			raise ValueError ('shift count should be positive')

		if o.y == 0:
			return Zero ()

		a = o

		for i in range (n):
			a = a._dbl ()

		return a

	def _add (a, b):
		(x, y) = swa_add (a.curve.a, a.x, a.y, b.x, b.y)

		return Point (a.curve, x, y)

	def __add__ (o, other):
		if isinstance (other, Zero):
			return o

		if not isinstance (other, Point):
			raise ValueError ('cannot add point to non-point')

		if o.curve != other.curve:
			raise ValueError ('cannot add points from different curves')

		if o.x == other.x:
			if o.y == other.y:
				return o._dbl ()
			else:
				return Zero ()

		return o._add (other)

	__radd__ = __add__

	#
	# Double-and-add
	#
	def _mul (P, d):
		N = P
		Q = Zero ()

		while d != 0:
			if (d & 1) != 0:
				Q += N

			N <<= 1
			d >>= 1

		return Q

	def __mul__ (o, n):
		if not isinstance (n, int):
			raise ValueError ('cannot multiply by non-integer')

		return o._mul (n)

	__rmul__ = __mul__

class SecurePoint (Point):
	#
	# Montgomery ladder
	#
	def _mul (P, d):
		R0 = Zero ()
		R1 = P
		mask = 1 << (d.bit_length () - 1)

		while mask != 0:
			if (d & mask) == 0:
				R1 += R0
				R0 <<= 1
			else:
				R0 += R1
				R1 <<= 1

			mask = mask >> 1

		return R0

def swa_dbl (a, x1, y1):
	l = (3 * x1 ** 2 + a) / (2 * y1)

	x = l ** 2 - 2 * x1
	y = l * (x1 - x) - y1

	return (x, y)

def swa_add (a, x1, y1, x2, y2):
	dx = x2 - x1
	dy = y2 - y1
	l  = dy / dx

	x = l ** 2 - x1 - x2
	y = l * (x1 - x) - y1

	return (x, y)

class Group (object):
	def __init__ (o, a, b, p, x, y, q):
		o.curve = Curve (a, b, p)
		o.x = x
		o.y = y
		o.q = q
