<?php

header('Content-Type: text/plain');

// Just call genSignalSafetyNumbers() with your fingerprint and phone number
// in international format as just numbers and a plus sign (ie "+12223335555")

function genSignalSafetyNumbers($publicKey, $phoneNumber)
{
	// is valid public key/fingerprint
	if (strlen($publicKey) == 98 && preg_match('/^05 ([0-9a-f][0-9a-f] ){31}[0-9a-f][0-9a-f]$/i', $publicKey))
	{
		$publicKey = hex2bin(str_replace(' ', '', $publicKey));
	}
	if (strlen($publicKey) == 66 && preg_match('/^05[0-9a-f]*$/i', $publicKey))
	{
		$publicKey = hex2bin($publicKey);
	}
	else if (strlen($publicKey) == 64 && preg_match('/^[0-9a-f]*$/i', $publicKey))
	{
		$publicKey = "\x05" . hex2bin($publicKey);
	}
	else if (strlen($publicKey) == 32)
	{
		$publicKey = "\x05" . $publicKey;
	}
	else if (strlen($publicKey) != 33 || $publicKey[0] != "\x05")
	{
		return "bad public key";
	}


	// Generate
	$hash = hex2bin('0000') . $publicKey . $phoneNumber;
	for ($i = 0; $i < 5200; $i++)
	{
		$hash = hash('sha512', $hash . $publicKey, true);
	}

	$ret = '';
	for ($i = 0; $i < 6; $i++)
	{
		$int = substr($hash, 5 * $i, 5);
		$int = gmp_init(bin2hex($int), 16);
		$int = gmp_mod($int, 100000);
		$ret .= substr('0000' . gmp_strval($int), -5) . ' ';
	}
	return substr($ret, 0, -1);
}

echo "30035 44776 92869 39689 28698 76765 45825 75691 62576 84344 09180 79131\n";
echo genSignalSafetyNumbers('05 06 86 3b c6 6d 02 b4 0d 27 b8 d4 9c a7 c0 9e 92 39 23 6f 9d 7d 25 d6 fc ca 5c e1 3c 70 64 d8 68', '+14152222222') . ' ';
echo genSignalSafetyNumbers('05 f7 81 b6 fb 32 fe d9 ba 1c f2 de 97 8d 4d 5d a2 8d c3 40 46 ae 81 44 02 b5 c0 db d9 6f da 90 7b', '+14153333333') . "\n";
