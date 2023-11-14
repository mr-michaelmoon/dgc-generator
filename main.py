from zlib import compress
from binascii import unhexlify
from cbor2 import dumps, CBORTag

from base45 import b45encode
from flynn import decoder as flynn_decoder
import qrcode
from cose.messages import Sign1Message
from cose.headers import Algorithm, KID
from cose.algorithms import Es256
from cose.keys.curves import P256
from cose.keys import EC2Key

VACC = {
	4: 1699747200,
	6: 1641027676,
	1: "IT",
	-260: {
		1: {
			"v": [{
				"dn": 3,
				"ma": "ORG-100030215",
				"vp": "1119349007",
				"dt": "2021-12-31",
				"co": "IT",
				"ci": "01IT805CEF3BD42E45EF9E270C5A16924986#0",
				"mp": "EU/1/20/1528",
				"is": "Ministero della Salute",
				"sd": 3,
				"tg": "840539006"
			}],
			"nam": {
				"fnt": "SURNAME",
				"fn": "Surname",
				"gnt": "NAME",
				"gn": "Name"
			},
			"ver": "1.3.0",
			"dob": "1800-01-01"
		}
	}
}

TEST = {
	4: 1699747200,
	6: 1642066979,
	1: "IT",
	-260: {
		1: {
			"t": [{
				"sc": "2022-01-13T10:33:00+01:00",
				"ma": "1363",
				"tt": "LP217198-3",
				"co": "IT",
				"tc": "RAPID",
				"ci": "01IT1033EEA681CC4795A0DFC653C3FE0677#1",
				"is": "Ministero della Salute",
				"tg": "840539006",
				"tr": "260415000"
			}],
			"nam": {
				"fnt": "SURNAME",
				"fn": "Surname",
				"gnt": "NAME",
				"gn": "Name"
			},
			"ver": "1.3.0",
			"dob": "1800-01-01"
		}
	}
}

RECV = {
	4: 1699747200,
	6: 1644481211,
	1: "IT",
	-260: {
		1: {
			"r": [{
				"du": "2022-07-26",
				"co": "IT",
				"ci": "01IT3BB15EFA4A034FF0874B3DEFB6041ECA#5",
				"is": "Ministero della Salute",
				"tg": "840539006",
				"df": "2022-02-07",
				"fr": "2022-01-27"
			}],
			"nam": {
				"fnt": "SURNAME",
				"fn": "Surname",
				"gnt": "NAME",
				"gn": "Name"
			},
			"ver": "1.3.0",
			"dob": "1800-01-01"
		}
	}
}

PRIVKEY = b"304502205D36C37AC5675CC8603280927F36F0D29016AAFEE85D423199C84A57"

HEADER = ""

def main():

	CBOR = dumps(RECV)

	msg = Sign1Message(phdr={Algorithm: Es256, KID: b"ceb332b481f8d119"}, payload=CBOR)

	private_key = unhexlify(PRIVKEY)
	cose_key = EC2Key(crv=P256, d=private_key, optional_params={"ALG": "ES256"})

	msg.key = cose_key

	signed_encoded = msg.encode()

	(cbor_tag, (header_1, header_2, cbor_payload, sign)) = flynn_decoder.loads(signed_encoded)

	if HEADER:
		header_1 = HEADER

	COSE = dumps(CBORTag(cbor_tag, (header_1, header_2, cbor_payload, sign)))

	ZLIB = compress(COSE)

	BASE45 = b45encode(ZLIB)
	
	b = str(BASE45)
	BASE45 = str()
	for e in b:
		if e == '\'' or e == 'b':
			pass
		else:
			BASE45 += e

	PREFIX = str("HC1:" + BASE45)

	qr_encoded = qrcode.make(b"HC1:" + b45encode(ZLIB))
	qr_encoded.save("./fake_r.png")
	print(PREFIX)

if __name__ == "__main__":
	main()
