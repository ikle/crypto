#!/usr/bin/python3

class Fp:
	def __init__ (o, x, p):
		if p == 0:
			raise ValueError ('order cannot be zero')

		o.p = int (p)
		o.x = int (x)

		if o.x < 0 or o.x >= o.p:
			o.x = o.x % p

	def __repr__ (o):
		return ' {} (mod {})'.format (o.x, o.p)

	def __int__ (o):
		return o.x

	def _egcd (o):
		(v, u) = (0, 1)
		(a, b) = (o.p, o.x)

		while b != 0:
			q = a // b

			a, b = b, a - q * b
			v, u = u, v - q * u

		return (a, v)

	def inverse (o):
		# x^-1 × x ≡ 1 (mod p)

		(r, v) = o._egcd ()

		if r != 1:
			raise ValueError ('cannot invert value')

		if v < 0:
			v = v + o.p

		return Fp (v, o.p)

	def __eq__ (o, a):
		if isinstance (a, Fp) and o.p != a.p:
			return False

		return o.x == int (a) % o.p

	def __neg__ (o):
		return Fp (o.p - o.x, o.p)

	def _validate (o, a):
		if isinstance (a, Fp) and a.p != o.p:
			raise ValueError ('incompatible order')

	def __add__ (o, a):
		o._validate (a)

		return Fp (o.x + int (a), o.p)

	# field is a ring (and an abelian group under addition)
	__radd__ = __add__

	def __sub__ (o, a):
		o._validate (a)

		return Fp (o.x - int (a), o.p)

	def __rsub__ (o, a):
		o._validate (a)

		return Fp (int (a) - o.x, o.p)

	def __mul__ (o, a):
		o._validate (a)

		return Fp (o.x * int (a), o.p)

	# field is a commutative ring
	__rmul__ = __mul__

	def __lshift__ (o, n):
		return Fp (o.x << n, o.p)

	def __rshift__ (o, n):
		return Fp (o.x >> n, o.p)

	def __floordiv__ (o, a):
		o._validate (a)

		if not isinstance (a, Fp):
			a = Fp (a, o.p)

		return o * a.inverse ()

	__truediv__ = __floordiv__

	def __rfloordiv__ (o, a):
		o._validate (a)

		return a * o.inverse ()

	__rtruediv__ = __rfloordiv__

	def __pow__ (o, a):
		o._validate (a)

		n = int (a)

		if n >= 0:
			return Fp (pow (o.x, n, o.p), o.p)

		return Fp (pow (o.x, -n, o.p), o.p).inverse ()
