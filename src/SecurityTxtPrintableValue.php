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
		return self::encode($value);
	}


	/**
	 * Only a URL with a scheme this library would fetch is printed as it reads. Any other scheme has an opaque path, serialised with a far smaller set of characters escaped, so
	 * what is safe in one is not established by what is safe in the other, and this library has no reason to vouch for a scheme it would never fetch.
	 */
	private static function renderUrl(Url $url): string
	{
		return in_array($url->getScheme(), ['http', 'https'], true)
			? $url->toUnicodeString()
			: self::encode($url->toUnicodeString());
	}


	/**
	 * A value is a URL, a host, an IP address or a field value read from a `security.txt`, none of which needs more than printable ASCII to be understood, while one control
	 * character or bidirectional override in one changes what the whole message says, whether it is read on a terminal, in a log or on a page. Bytes rather than code points,
	 * so a value that is not valid UTF-8 is encoded as well, and `rawurlencode()` is the notation `Uri\WhatWg\Url` uses for the same bytes.
	 *
	 * Formats are not encoded, they are written in this codebase, and neither are the values a caller can ask for separately, which are the ones a caller that knows what it
	 * is rendering into should be escaping its own way.
	 */
	private static function encode(string $value): string
	{
		$encoded = preg_replace_callback(
			'/[^\x20-\x7e]/',
			function (array $matches): string {
				return rawurlencode($matches[0]);
			},
			$value,
		);
		// Fails closed, printing nothing beats printing what this method exists to encode
		return $encoded ?? '';
	}

}
