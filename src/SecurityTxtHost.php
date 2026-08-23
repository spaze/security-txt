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

	private bool $internationalized;


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
		$this->internationalized = in_array($url->getScheme(), ['http', 'https'], true) && $unicode !== $ascii;
	}


	/**
	 * The inverse of the serialized form, which is `getUnicode()`, and accepts exactly that, nothing else: a value that reads back as something other than itself, `808` becomes
	 * the IP address `0.0.3.40` and the punycode spelling becomes the host as it reads, is refused rather than rewritten, so whatever is accepted replays byte identical. Parsed
	 * under https, like the fetcher fetches, so `isInternationalized()` comes out the same whether the host lived through a check or through JSON.
	 *
	 * @throws SecurityTxtCannotParseHostnameException
	 */
	public static function fromString(string $host): self
	{
		$url = Url::parse("https://{$host}");
		if ($url === null || $url->getUnicodeHost() !== $host) {
			throw new SecurityTxtCannotParseHostnameException($host);
		}
		return new self($url);
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
	 * what IDNA deletes, a zero width space or a soft hyphen, leaves a host that really is what it reads as. Judged only for http and https, the schemes this library fetches:
	 * an opaque host skips IDNA and keeps its case, so a difference there is no signal.
	 */
	public function isInternationalized(): bool
	{
		return $this->internationalized;
	}

}
