<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Uri\WhatWg\Url;

/**
 * What this library does only because `Uri\WhatWg\Url` in PHP before 8.5.12 parses some URLs wrong, kept in one place: once PHP 8.5.12 is required, this class is deleted and
 * every place static analysis then reports goes back to doing without it.
 */
final class SecurityTxtPhpUrlWorkarounds
{

	/**
	 * A serialized URL is printable ASCII, but before PHP 8.5.12 the parser copied the two bytes after a `%` that starts no escape into the path unchecked, a NUL, an escape
	 * sequence or a byte that is not UTF-8 included (fixed by lexbor/lexbor@327a8b6, merged into php-src as beee5444d0).
	 */
	public static function hasRawBytes(Url $url): bool
	{
		return preg_match('/[^\x20-\x7E]/', $url->toAsciiString()) === 1;
	}

}
