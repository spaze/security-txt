<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Uri\WhatWg\Url;

/**
 * The host of a URL that parsed.
 *
 * Built from the URL rather than from a string on purpose: parsing refuses a host with a control character in it, so a host that came out of one cannot carry one and can be
 * printed as it reads. A host assembled from a string has no such thing behind it.
 */
final readonly class SecurityTxtHost
{

	private string $unicode;

	private string $ascii;


	/**
	 * @throws SecurityTxtCannotParseHostnameException
	 */
	public function __construct(Url $url)
	{
		$unicode = $url->getUnicodeHost();
		$ascii = $url->getAsciiHost();
		if ($unicode === null || $ascii === null) {
			throw new SecurityTxtCannotParseHostnameException($url->toUnicodeString());
		}
		$this->unicode = $unicode;
		$this->ascii = $ascii;
	}


	public function getUnicode(): string
	{
		return $this->unicode;
	}


	public function getAscii(): string
	{
		return $this->ascii;
	}


	/**
	 * The two forms differ, which is where a host that reads like another one would hide: a letter from another script or a joiner that survives IDNA forces punycode, while
	 * what IDNA deletes, a zero width space or a soft hyphen, leaves a host that really is what it reads as.
	 */
	public function isInternationalized(): bool
	{
		return $this->unicode !== $this->ascii;
	}

}
