<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\SecurityTxtContact;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Violations\SecurityTxtAcknowledgmentsNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtAcknowledgmentsNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtNotUriReason;
use Spaze\SecurityTxt\Violations\SecurityTxtPolicyNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtPolicyNotUri;
use Uri\Rfc3986\Uri;
use Uri\WhatWg\Url;

/**
 * Whether a value written in a `security.txt` is a URI, and why not when it is not, worked out together so the rule and the reason cannot disagree. RFC 9116 says a value
 * follows the URI syntax described in RFC 3986, so that decides, once the characters RFC 3987 adds for an IRI are percent-encoded as its Section 3.1 maps them, which makes
 * `https://háčky.example/` one. On top of that an HTTP or HTTPS URI needs a host and no user name, which RFC 9110 requires, and any URI has to be one the WHATWG parser this
 * library reads URLs with can parse, which a port of 99999 is not.
 */
final class SecurityTxtUriValidator
{

	/**
	 * The scheme RFC 3986 Section 3.1 describes
	 */
	private const string SCHEME = '[a-z][a-z0-9+.-]*';

	/**
	 * The scheme, `//`, and the user name and password up to the last `@` before the host, where RFC 3986 and the WHATWG parser both end them
	 */
	private const string BEFORE_HOST = self::SCHEME . '://(?:[^/?#]*@)?';

	/**
	 * The schemes RFC 9116 uses, a word before a colon that isn't one of them is more likely a label, like `Email: security@example.com`
	 */
	private const string KNOWN_SCHEMES = 'https?|mailto|tel|openpgp4fpr|dns';

	private const string CONTROL = '(?:[\x00-\x1f\x7f]|\xc2[\x80-\x9f])';


	/**
	 * @param class-string<SecurityTxtAcknowledgmentsNotUri|SecurityTxtCanonicalNotUri|SecurityTxtContactNotUri|SecurityTxtCsafNotUri|SecurityTxtEncryptionNotUri|SecurityTxtHiringNotUri|SecurityTxtPolicyNotUri|SecurityTxtFileLocationNotUri> $notUriError
	 * @param class-string<SecurityTxtAcknowledgmentsNotHttps|SecurityTxtCanonicalNotHttps|SecurityTxtContactNotHttps|SecurityTxtCsafNotHttps|SecurityTxtEncryptionNotHttps|SecurityTxtHiringNotHttps|SecurityTxtPolicyNotHttps|SecurityTxtFileLocationNotHttps> $notHttpsError
	 * @param bool $fetched The URL a file was fetched from is not written in the file but serialized by the parser, which leaves `|` or `%zz` in a path as they were, so it is refused only when the parser cannot read it at all
	 * @throws SecurityTxtError
	 */
	public function validate(string $uri, string $notUriError, string $notHttpsError, ?SecurityTxtField $field = null, bool $fetched = false): void
	{
		$result = $fetched ? $this->checkFetched($uri) : $this->check($uri, $field);
		if (!$result instanceof Url) {
			throw new SecurityTxtError(new $notUriError($uri, ...$result));
		}
		if ($result->getScheme() === 'http') {
			throw new SecurityTxtError(new $notHttpsError($uri));
		}
	}


	/**
	 * The URL a value is, or why it is not one and what to use instead, named as the violation's parameters. Without `$explain` only whether it is one, all a suggestion
	 * needs, so working out a suggestion never works out another one.
	 *
	 * @return Url|array{reason: SecurityTxtNotUriReason, correctValue?: string|null, character?: string}
	 */
	private function check(string $uri, ?SecurityTxtField $field, bool $explain = true): Url|array
	{
		// A value that isn't UTF-8 is not an IRI, and fails here
		$iri = preg_replace_callback('/[^\x00-\x7f]/u', fn(array $matches): string => $this->isUcschar($matches[0]) ? rawurlencode($matches[0]) : $matches[0], $uri);
		$rfc3986 = $iri === null ? null : Uri::parse($iri);
		$scheme = $rfc3986?->getScheme();
		if ($iri === null || $rfc3986 === null || $scheme === null) {
			return $explain ? $this->explainNotRfc3986($uri, $iri ?? $uri, $field) : ['reason' => SecurityTxtNotUriReason::NotRfc3986];
		}
		if (in_array($scheme, ['http', 'https'], true)) {
			if (in_array($rfc3986->getRawHost(), [null, ''], true)) {
				return ['reason' => SecurityTxtNotUriReason::HostMissing];
			}
			$userInfo = $rfc3986->getRawUserInfo();
			if ($userInfo !== null) {
				// Cut out of the value as written, a URL serialized by a parser would spell the rest the way the parser read it
				$withoutUserInfo = preg_replace('~^(' . self::SCHEME . '://)[^/?#]*@~i', '$1', $uri, 1);
				return [
					'reason' => $userInfo === '' ? SecurityTxtNotUriReason::EmptyUserInfo : SecurityTxtNotUriReason::UserInfo,
					'correctValue' => $explain ? $this->suggest($withoutUserInfo) : null,
				];
			}
		}
		$url = Url::parse($uri);
		if ($url === null) {
			if ($rfc3986->getPort() > 65535) {
				return ['reason' => SecurityTxtNotUriReason::PortOutOfRange];
			}
			return ['reason' => in_array($rfc3986->getRawHost(), [null, ''], true) ? SecurityTxtNotUriReason::HostMissing : SecurityTxtNotUriReason::InvalidHost];
		}
		return $url;
	}


	/**
	 * Why RFC 3986 refused a value, or read it as a relative reference, which is not a URI either for having no scheme, the first reason that holds. Worked out from the
	 * value, because the parser says only that it is malformed, but only for a value it refused, so whatever reason this gives, the value does break RFC 3986.
	 *
	 * @param string $iri The value with the characters RFC 3987 adds for an IRI percent-encoded, so what is left that is not ASCII is not allowed even there
	 * @return array{reason: SecurityTxtNotUriReason, correctValue?: string|null, character?: string}
	 */
	private function explainNotRfc3986(string $uri, string $iri, ?SecurityTxtField $field): array
	{
		// Words separated by spaces, commas or control characters, of which a scheme and `//`, or a scheme RFC 9116 uses and more, is a URI, not `ext:12` or `example.com:8080`
		$words = preg_split('/(?:[\s,]|' . self::CONTROL . ')++/', $uri, -1, PREG_SPLIT_NO_EMPTY);
		$uris = array_filter($words === false ? [] : $words, fn(string $word): bool => preg_match('~^(?:' . self::SCHEME . '://|(?:' . self::KNOWN_SCHEMES . '):).~i', $word) === 1);
		if (count($uris) > 1) {
			return ['reason' => SecurityTxtNotUriReason::MoreThanOneUri];
		}
		if ($this->isSchemeMissing($uri)) {
			return $this->explainSchemeMissing($uri, $field);
		}
		[$host, $port] = $this->getHostAndPort($uri);
		if (str_contains($uri, ' ')) {
			if (preg_match('/^tel:( *)(\+?[0-9\-. ]+)$/iD', $uri, $matches) === 1 && str_contains($matches[2], ' ')) {
				return [
					'reason' => $matches[1] === '' ? SecurityTxtNotUriReason::SpaceInPhoneNumber : SecurityTxtNotUriReason::SpaceAfterSchemeAndInPhoneNumber,
					'correctValue' => $this->suggest(SecurityTxtContact::phone($matches[2])->getUri()),
				];
			}
			if (preg_match('/^(' . self::KNOWN_SCHEMES . '): +(\S+)$/iD', $uri, $matches) === 1) {
				return ['reason' => SecurityTxtNotUriReason::SpaceAfterScheme, 'correctValue' => $this->suggest("{$matches[1]}:{$matches[2]}")];
			}
			// In the host or the port only if the path or something else follows them, with nothing after the host, a space may as well end the URI and start a note
			$authority = preg_match('~^' . self::SCHEME . '://[^/?#]*+[/?#]~i', $uri) === 1;
			return ['reason' => match (true) {
				$authority && str_contains($host ?? '', ' ') => SecurityTxtNotUriReason::SpaceInHost,
				$authority && str_contains($port ?? '', ' ') => SecurityTxtNotUriReason::SpaceInPort,
				default => SecurityTxtNotUriReason::Space,
			}];
		}
		if (preg_match('/' . self::CONTROL . '/', $uri) === 1) {
			// Unless that would join what the control characters separate, a word to a word or one host label to another
			$joins = preg_match('~(?<=[^:/?#@])(?<!' . self::CONTROL . ')' . self::CONTROL . '++(?=[^:/?#@])~', $uri) === 1;
			return ['reason' => SecurityTxtNotUriReason::ControlCharacter, 'correctValue' => $joins ? null : $this->suggest(preg_replace('/' . self::CONTROL . '/', '', $uri))];
		}
		$percent = '/%(?![0-9a-f]{2})/i';
		if (preg_match($percent, $uri) === 1) {
			if (preg_match($percent, $host ?? '') === 1) {
				return ['reason' => SecurityTxtNotUriReason::StrayPercentInHost];
			}
			return ['reason' => SecurityTxtNotUriReason::StrayPercent, 'correctValue' => $this->suggest(preg_replace($percent, '%25', $uri))];
		}
		if (str_contains($uri, '\\')) {
			return ['reason' => SecurityTxtNotUriReason::Backslash];
		}
		if ($host !== null && str_starts_with($host, '[') && !str_contains($host, ']')) {
			return ['reason' => SecurityTxtNotUriReason::Ipv6Unclosed];
		}
		// What follows the last colon is the port only when the host is in square brackets or has no colon, in `2001:db8::ff` it is part of the address
		[$knownHost, $knownPort] = str_starts_with($host ?? '', '[') || !str_contains($host ?? '', ':') ? [$host, $port] : ["{$host}:{$port}", null];
		// A `[` and a `]` are allowed only around an IPv6 address, and a `#` only once
		$rest = preg_replace('~^(' . self::BEFORE_HOST . ')\[[^/?#\]]*\]~i', '$1', $iri) ?? $iri;
		$fragment = strpos($rest, '#');
		if (
			preg_match("~[^a-z0-9._\\~:/?#@!$&'()*+,;=%-]|\\[|\\]~i", $rest, $matches) === 1
			|| (
				$fragment !== false
				&& preg_match('/#/', $rest, $matches, 0, $fragment + 1) === 1
			)
		) {
			return match (true) {
				str_contains($knownPort ?? '', $matches[0]) => ['reason' => SecurityTxtNotUriReason::PortNotNumber],
				preg_match('/^[\x21-\x7e]$/D', $matches[0]) !== 1 => ['reason' => SecurityTxtNotUriReason::UnencodedCharacter],
				// Percent-encoded it would still not be a host, an IPv6 address was left out of the search
				!str_starts_with($knownHost ?? '', '[') && str_contains($knownHost ?? '', $matches[0]) => ['reason' => SecurityTxtNotUriReason::CharacterInHost, 'character' => $matches[0]],
				default => ['reason' => SecurityTxtNotUriReason::Character, 'character' => $matches[0]],
			};
		}
		if ($host !== null && !str_starts_with($host, '[') && substr_count("{$host}:{$port}", ':') > 1) {
			$bracketed = preg_replace('~^(' . self::BEFORE_HOST . ')([^/?#]*)~i', '$1[$2]', $uri, 1);
			$withPort = $port !== null && preg_match('/^[0-9]{2,}$/D', $port) === 1 ? preg_replace('~^(' . self::BEFORE_HOST . ')([^/?#]*):~i', '$1[$2]:', $uri, 1) : null;
			// Which of them are URIs, `http` ones too, the scheme is not what is wrong with the value
			$uris = array_values(array_filter([$bracketed, $withPort], fn(?string $value): bool => $value !== null && $this->check($value, null, explain: false) instanceof Url));
			if ($uris !== []) {
				// Not when both are, `2001:db8::1:8080` is one address, or another one and a port
				return ['reason' => SecurityTxtNotUriReason::Ipv6WithoutBrackets, 'correctValue' => count($uris) === 1 ? $this->suggest($uris[0]) : null];
			}
		}
		if ($knownPort !== null && preg_match('/^[0-9]*$/D', $knownPort) !== 1) {
			return ['reason' => SecurityTxtNotUriReason::PortNotNumber];
		}
		return ['reason' => SecurityTxtNotUriReason::NotRfc3986];
	}


	/**
	 * @return array{reason: SecurityTxtNotUriReason, correctValue?: string|null}
	 */
	private function explainSchemeMissing(string $uri, ?SecurityTxtField $field): array
	{
		if ($field === SecurityTxtField::Contact) {
			[$reason, $correctValue] = match (true) {
				filter_var($uri, FILTER_VALIDATE_EMAIL) !== false => [SecurityTxtNotUriReason::SchemeMissingEmail, SecurityTxtContact::email($uri)->getUri()],
				preg_match('/^\+?[0-9\-. ]+$/D', $uri) === 1 => [
					str_contains($uri, ' ') ? SecurityTxtNotUriReason::SchemeMissingPhoneWithSpaces : SecurityTxtNotUriReason::SchemeMissingPhone,
					SecurityTxtContact::phone($uri)->getUri(),
				],
				default => [SecurityTxtNotUriReason::SchemeMissingHostname, "https://{$uri}"],
			};
			// Prose with an @ in it does not become a URI by putting a scheme in front, and the hint saying it would goes with the suggestion
			$correctValue = $this->suggest($correctValue);
			if ($correctValue !== null) {
				return ['reason' => $reason, 'correctValue' => $correctValue];
			}
		}
		return ['reason' => SecurityTxtNotUriReason::SchemeMissing];
	}


	/**
	 * The host and the port as written, each null when the value has no authority, or the authority no port. An IPv6 address ends at its `]`.
	 *
	 * @return array{string|null, string|null}
	 */
	private function getHostAndPort(string $uri): array
	{
		if (preg_match('~^' . self::BEFORE_HOST . '([^/?#]*)~i', $uri, $matches) !== 1) {
			return [null, null];
		}
		$authority = $matches[1];
		$end = str_starts_with($authority, '[') ? strpos($authority, ']') : false;
		if ($end !== false) {
			$rest = substr($authority, $end + 1);
			return [substr($authority, 0, $end + 1), str_starts_with($rest, ':') ? substr($rest, 1) : null];
		}
		$colon = strrpos($authority, ':');
		return $colon === false ? [$authority, null] : [substr($authority, 0, $colon), substr($authority, $colon + 1)];
	}


	/**
	 * @return Url|array{reason: SecurityTxtNotUriReason}
	 */
	private function checkFetched(string $uri): Url|array
	{
		return Url::parse($uri) ?? ['reason' => $this->isSchemeMissing($uri) ? SecurityTxtNotUriReason::SchemeMissing : SecurityTxtNotUriReason::NotUrl];
	}


	/**
	 * A value to use instead, but only one that passes the checks the value failed, this one and the one after it refusing `http`.
	 */
	private function suggest(?string $value): ?string
	{
		if ($value === null) {
			return null;
		}
		$result = $this->check($value, null, explain: false);
		return $result instanceof Url && $result->getScheme() !== 'http' ? $value : null;
	}


	/**
	 * Whether a character is one RFC 3987 adds for an IRI, its `ucschar`, leaving out the private use characters it also allows in a query, no `security.txt` needs them.
	 * Compared as a number, not as a character class in a pattern: PCRE2 10.46 fails to match `例` against the class with all of the ranges below.
	 */
	private function isUcschar(string $character): bool
	{
		$codePoint = match (strlen($character)) {
			2 => (ord($character[0]) & 0x1f) << 6 | ord($character[1]) & 0x3f,
			3 => (ord($character[0]) & 0x0f) << 12 | (ord($character[1]) & 0x3f) << 6 | ord($character[2]) & 0x3f,
			4 => (ord($character[0]) & 0x07) << 18 | (ord($character[1]) & 0x3f) << 12 | (ord($character[2]) & 0x3f) << 6 | ord($character[3]) & 0x3f,
			default => 0,
		};
		return ($codePoint >= 0xa0 && $codePoint <= 0xd7ff)
			|| ($codePoint >= 0xf900 && $codePoint <= 0xfdcf)
			|| ($codePoint >= 0xfdf0 && $codePoint <= 0xffef)
			// From %x10000-1FFFD to %xD0000-DFFFD, and %xE1000-EFFFD
			|| ($codePoint >= 0x10000 && $codePoint <= 0xefffd && ($codePoint & 0xffff) <= 0xfffd && ($codePoint < 0xe0000 || $codePoint >= 0xe1000));
	}


	private function isSchemeMissing(string $uri): bool
	{
		return preg_match('/^' . self::SCHEME . ':/i', $uri) !== 1;
	}

}
