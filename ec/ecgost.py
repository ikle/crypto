#!/usr/bin/python3
#
# GOST Elliptic Curve Digital Signature
#
# Copyright (c) 2016-2018 Alexei A. Smekalkine <ikle@ikle.ru>
#
# Standard: GOST R 34.10-2001, GOST R 34.10-2012
# Standard: RFC 4357, RFC 7836
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
	if name == 'ecgost-test-a' or \
	   name == 'id-GostR3410-2001-TestParamSet' or \
	   name == '1.2.643.2.2.35.0':
		a = 0x7
		b = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
		p = 0x8000000000000000000000000000000000000000000000000000000000000431
		x = 0x2
		y = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8
		q = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
		return Group (a, b, p, x, y, q)

	if name == 'ecgost-cpro-a' or \
	   name == 'id-GostR3410-2001-CryptoPro-A-ParamSet' or \
	   name == '1.2.643.2.2.35.1' or \
	   name == 'ecgost-cpro-xcha' or \
	   name == 'id-GostR3410-2001-CryptoPro-XchA-ParamSet' or \
	   name == '1.2.643.2.2.36.0':
		a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94
		b = 0xA6
		p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
		x = 0x1
		y = 0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14
		q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893
		return Group (a, b, p, x, y, q)

	if name == 'ecgost-cpro-b' or \
	   name == 'id-GostR3410-2001-CryptoPro-B-ParamSet' or \
	   name == '1.2.643.2.2.35.2':
		a = 0x8000000000000000000000000000000000000000000000000000000000000C96
		b = 0x3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B
		p = 0x8000000000000000000000000000000000000000000000000000000000000C99
		x = 0x1
		y = 0x3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC
		q = 0x800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F
		return Group (a, b, p, x, y, q)

	if name == 'ecgost-cpro-c' or \
	   name == 'id-GostR3410-2001-CryptoPro-C-ParamSet' or \
	   name == '1.2.643.2.2.35.3' or \
	   name == 'ecgost-cpro-xchb' or \
	   name == 'id-GostR3410-2001-CryptoPro-XchB-ParamSet' or \
	   name == '1.2.643.2.2.36.1':
		a = 0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598
		b = 0x805a
		p = 0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B
		x = 0x0
		y = 0x41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67
		q = 0x9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9
		return Group (a, b, p, x, y, q)

	if name == 'ecgost-test-b' or \
	   name == 'id-tc26-gost-3410-12-512-paramSetTest' or \
	   name == '1.2.643.7.1.2.1.2.0':
		a = 0x7
		b = 0x1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC
		p = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373
		x = 0x24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A
		y = 0x2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E
		q = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF
		return Group (a, b, p, x, y, q)

	if name == 'ecgost-tc26-512-a' or \
	   name == 'id-tc26-gost-3410-12-512-paramSetA' or \
	   name == '1.2.643.7.1.2.1.2.1':
		a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4
		b = 0xE8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760
		p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7
		x = 0x3
		y = 0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4
		q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
		return Group (a, b, p, x, y, q)

	if name == 'ecgost-tc26-512-b' or \
	   name == 'id-tc26-gost-3410-12-512-paramSetB' or \
	   name == '1.2.643.7.1.2.1.2.2':
		a = 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C
		b = 0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116
		p = 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F
		x = 0x2
		y = 0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD
		q = 0x800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD
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
