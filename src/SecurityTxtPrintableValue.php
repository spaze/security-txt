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
	 * there is nothing left in one to encode. Printed as it reads, with the ASCII host alongside when the two differ, which is when the readable form has something in it that
	 * could pass for another host. Anything else is a string this library cannot vouch for, and is encoded down to printable ASCII.
	 */
	public static function render(string|Url|SecurityTxtHost $value): string
	{
		if ($value instanceof SecurityTxtHost) {
			return $value->isInternationalized() ? sprintf('%s (%s)', $value->getUnicode(), $value->getAscii()) : $value->getUnicode();
		}
		if ($value instanceof Url) {
			return self::renderUrl($value);
		}
		return SecurityTxtPrintableAscii::encode($value);
	}


	/**
	 * Only a URL with a scheme this library would fetch is printed as it reads. Any other scheme has an opaque path, serialised with a far smaller set of characters escaped, so
	 * a space or a bracket in it arrives the way a host wrote it, and a host that IDNA never touched, so the two forms of it differ by letter case alone and would raise the
	 * lookalike signal for a plain ASCII name.
	 */
	private static function renderUrl(Url $url): string
	{
		if (!in_array($url->getScheme(), ['http', 'https'], true)) {
			return SecurityTxtPrintableAscii::encode($url->toUnicodeString());
		}
		$asciiHost = $url->getAsciiHost();
		return $asciiHost !== null && $asciiHost !== $url->getUnicodeHost()
			? sprintf('%s (%s)', $url->toUnicodeString(), $asciiHost)
			: $url->toUnicodeString();
	}

}
