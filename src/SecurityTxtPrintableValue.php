<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Uri\WhatWg\Url;

/**
 * How a value read from a checked host is turned into something safe to print.
 *
 * One rule, used both where a violation renders its message and where the console prints one, so the two cannot say the same value differently.
 */
final class SecurityTxtPrintableValue
{

	/**
	 * A `Url` and a `SecurityTxtHost` exist only because they parsed, and parsing rejects a host with a control character in it and percent encodes everything after the host, so
	 * there is nothing left in one to encode and it is printed as it reads. Anything else is a string this library cannot vouch for, and is encoded down to printable ASCII.
	 */
	public static function render(string|Url|SecurityTxtHost $value): string
	{
		if ($value instanceof SecurityTxtHost) {
			return $value->getUnicode();
		}
		if ($value instanceof Url) {
			return self::renderUrl($value);
		}
		return SecurityTxtPrintableAscii::encode($value);
	}


	/**
	 * Only a URL with a scheme this library would fetch is printed as it reads. Any other scheme has an opaque path, serialised with a far smaller set of characters escaped, so
	 * what is safe in one is not established by what is safe in the other, and this library has no reason to vouch for a scheme it would never fetch.
	 */
	private static function renderUrl(Url $url): string
	{
		return in_array($url->getScheme(), ['http', 'https'], true)
			? $url->toUnicodeString()
			: SecurityTxtPrintableAscii::encode($url->toUnicodeString());
	}

}
