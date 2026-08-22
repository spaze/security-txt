<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

final class SecurityTxtPrintableAscii
{

	/**
	 * A value is a URL, a host, an IP address or a field value read from a `security.txt`, none of which needs more than printable ASCII to be understood, while one control
	 * character or bidirectional override in one changes what the whole message says, whether it is read on a terminal, in a log or on a page. Bytes rather than code points,
	 * so a value that is not valid UTF-8 is encoded as well, and `rawurlencode()` is the notation `Uri\WhatWg\Url` uses for the same bytes.
	 *
	 * Formats are not encoded, they are written in this codebase, and neither are the values a caller can ask for separately, which are the ones a caller that knows what it
	 * is rendering into should be escaping its own way.
	 */
	public static function encode(string $value): string
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
