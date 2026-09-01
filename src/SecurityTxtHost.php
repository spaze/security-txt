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
	 * The URL has to be settled, which is what `SecurityTxtUrlParser::normalize()` does: parsing decodes a percent escape in the host without folding the case it uncovers,
	 * so `https://ex%41mple.com/` has the host `exAmple.com`, a spelling that reads back as `example.com` and so cannot be rebuilt from what this would print.
	 *
	 * @throws SecurityTxtCannotParseHostnameException
	 */
	public function __construct(Url $url)
	{
		$ascii = $url->getAsciiHost();
		$decoded = $url->getUnicodeHost();
		// A URL parsing to a readable host of `''` has a label that is not valid punycode, and nothing resolves it. A URL that parses again as something else has not been
		// settled, and a host taken from one would read as a spelling it cannot be rebuilt from, so the caller settles it first
		if (
			$ascii === null
			|| $decoded === null
			|| $decoded === ''
			|| Url::parse($url->toAsciiString())?->getAsciiHost() !== $ascii
		) {
			throw new SecurityTxtCannotParseHostnameException($url->toUnicodeString());
		}
		$this->ascii = $ascii;
		$this->unicode = self::readable($ascii, $decoded);
	}


	/**
	 * Which spelling this host reads as. Decoding an A-label is not always reversible: `xn--khby` decodes to U+0648 U+0654, which encodes back as `xn--jgb`, so the decoded
	 * spelling would name a different host than the one that was asked for. Decided per label, the way browsers decide it: a label decodes only when the host with just that
	 * label decoded still encodes back to the same host, so `xn--bcher-kva.xn--khby.example` reads as `bücher.xn--khby.example` rather than losing the readable label to the
	 * one next to it. Judged in place, not alone, because a lone label can encode differently than it does beside a neighbour: `xn--wuao` decoded re-encodes as itself alone
	 * and as `xn--wuan` in a domain. The assembled name has to encode back as a whole too, the bidi rule reads across labels, or the host reads as its A-labels.
	 */
	private static function readable(string $ascii, string $decoded): string
	{
		if (self::encodesTo($decoded, $ascii)) {
			return $decoded;
		}
		$asciiLabels = explode('.', $ascii);
		$decodedLabels = explode('.', $decoded);
		if (count($asciiLabels) !== count($decodedLabels)) {
			return $ascii;
		}
		$labels = $asciiLabels;
		foreach ($decodedLabels as $key => $decodedLabel) {
			$spliced = $asciiLabels;
			$spliced[$key] = $decodedLabel;
			if (self::encodesTo(implode('.', $spliced), $ascii)) {
				$labels[$key] = $decodedLabel;
			}
		}
		$name = implode('.', $labels);
		return self::encodesTo($name, $ascii) ? $name : $ascii;
	}


	private static function encodesTo(string $spelling, string $ascii): bool
	{
		return Url::parse("https://{$spelling}")?->getAsciiHost() === $ascii;
	}


	/**
	 * The inverse of the serialized form, which is `getUnicode()`, and accepts exactly that, nothing else: a value that reads back as something other than itself, `808` becomes
	 * the IP address `0.0.3.40`, is refused rather than rewritten, so whatever is accepted replays byte identical. Parsed under HTTPS, like the fetcher fetches, so the two forms
	 * come out the same whether the host lived through a check or through JSON.
	 *
	 * @throws SecurityTxtCannotParseHostnameException
	 */
	public static function fromString(string $host): self
	{
		$url = Url::parse("https://{$host}");
		if ($url === null) {
			throw new SecurityTxtCannotParseHostnameException($host);
		}
		try {
			$self = new self($url);
		} catch (SecurityTxtCannotParseHostnameException $e) {
			// The constructor names the URL it was handed, which is one this method derived; a caller of this one asked about a host and gets told about that host
			throw new SecurityTxtCannotParseHostnameException($host, $e);
		}
		if ($self->getUnicode() !== $host) {
			throw new SecurityTxtCannotParseHostnameException($host);
		}
		return $self;
	}


	public function getUnicode(): string
	{
		return $this->unicode;
	}


	public function getAscii(): string
	{
		return $this->ascii;
	}

}
