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

def mp_sqr (a):		return a ** 2
def mp_add (a, b):	return a + b
def mp_sub (a, b):	return a - b
def mp_sal (a, n):	return a << n
def mp_mul (a, b):	return a * b

def dbl_2007_bl (A, x1, y1, z1):
	t0 = mp_sqr (y1)	# t0 = yy
	t1 = mp_sqr (z1)	# t1 = zz

	z3 = mp_add (y1, z1)	# z3 = y1 + z1
	z3 = mp_sqr (z3)	# z3 = (y1 + z1)^2
	z3 = mp_sub (z3, t0)	# z3 = (y1 + z1)^2 - yy
	z3 = mp_sub (z3, t1)	# z3 = (y1 + z1)^2 - yy - zz

	y3 = mp_sqr (t0)	# y3 = yyyy
	t0 = mp_add (t0, x1)	# t0 = x1 + yy
	t0 = mp_sqr (t0)	# t0 = (x1 + yy)^2
	x3 = mp_sqr (x1)	# x3 = xx
	t0 = mp_sub (t0, x3)	# t0 = (x1 + yy)^2 - xx
	t0 = mp_sub (t0, y3)	# t0 = (x1 + yy)^2 - xx - yyyy
	t0 = mp_sal (t0, 1)	# t0 = 2 ((x1 + yy)^2 - xx - yyyy) = s

	x3 = mp_mul (x3, 3)	# x3 = 3 xx
	t1 = mp_sqr (t1)	# t1 = zzzz
	t1 = mp_mul (t1, A)	# t1 = a zzzz
	t1 = mp_add (t1, x3)	# t1 = 3 xx + a zzzz = m
	x3 = mp_sqr (t1)	# x3 = m^2
	t2 = mp_sal (t0, 1)	# t2 = 2s
	x3 = mp_sub (x3, t2)	# x3 = m^2 - 2s

	t0 = mp_sub (t0, x3)	# t0 = s - x3
	t0 = mp_mul (t1, t0)	# t0 = m (s - x3)
	y3 = mp_sal (y3, 3)	# y3 = 8 yyyy
	y3 = mp_sub (t0, y3)	# y3 = m (s - x3) - 8 yyyy

	return (x3, y3, z3)

def add_2007_bl (x1, y1, z1, x2, y2, z2):
	t0 = mp_sqr (z1)	# t0 = z1z1
	t1 = mp_sqr (z2)	# t1 = z2z2
	t2 = mp_mul (x1, t1)	# t2 = x1 z2z2 = u1
	t3 = mp_mul (x2, t0)	# t3 = x2 z1z1 = u2		x3 gone
	t4 = mp_mul (y1, z2)	# t4 = y1 z2
	t4 = mp_mul (t4, t1)	# t4 = y1 z2z2z2 = s1
	t5 = mp_mul (y2, z1)	# t5 = y2 z1			y3 gone
	t5 = mp_mul (t5, t0)	# t5 = y2 z1z1z1 = s2
	t3 = mp_sub (t3, t2)	# t3 = u2 - u1 = h

	z3 = mp_add (z1, z2)	# z3 = z1 + z2
	z3 = mp_sqr (z3)	# z3 = (z1 + z2)^2
	z3 = mp_sub (z3, t0)	# z3 = (z1 + z2)^2 - z1z1
	z3 = mp_sub (z3, t1)	# z3 = (z1 + z2)^2 - z1z1 - z2z2
	z3 = mp_mul (z3, t3)	# z3 = ((z1 + z2)^2 - z1z1 - z2z2) h

	y3 = mp_sal (t3, 1)	# y3 = 2h
	y3 = mp_sqr (y3)	# y3 = (2h)^2
	t3 = mp_mul (t3, y3)	# t3 = hi = j
	t5 = mp_sub (t5, t4)	# t5 = s2 - s1
	t5 = mp_sal (t5, 1)	# t5 = 2 (s2 - s1) = r
	y3 = mp_mul (y3, t2)	# y3 = u1 i = v			t2 gone

	x3 = mp_sqr (t5)	# x3 = r^2
	x3 = mp_sub (x3, t3)	# x3 = r^2 - j
	t2 = mp_sal (y3, 1)	# t2 = 2v
	x3 = mp_sub (x3, t2)	# x3 = r^2 - j - 2v		t2 gone

	y3 = mp_sub (y3, x3)	# y3 = v - x3
	y3 = mp_mul (y3, t5)	# y3 = r (v - x3)
	t4 = mp_mul (t4, t3)	# t4 = s1 j
	t4 = mp_sal (t4, 1)	# t4 = 2 s1 j
	y3 = mp_sub (y3, t4)	# y3 = r (v - x3) - 2 s1 j

	return (x3, y3, z3)
