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
	 * The URL a value is, or why it is not one and what to use instead. Without `$explain` only whether it is one, all a suggestion needs, so working out a suggestion
	 * never works out another one.
	 *
	 * @return Url|array{SecurityTxtNotUriReason, string|null}
	 */
	private function check(string $uri, ?SecurityTxtField $field, bool $explain = true): Url|array
	{
		// A value that isn't UTF-8 is not an IRI, and fails here
		$iri = preg_replace_callback('/[^\x00-\x7f]/u', fn(array $matches): string => $this->isUcschar($matches[0]) ? rawurlencode($matches[0]) : $matches[0], $uri);
		$rfc3986 = $iri === null ? null : Uri::parse($iri);
		$scheme = $rfc3986?->getScheme();
		if ($iri === null || $rfc3986 === null || $scheme === null) {
			return $explain ? $this->explainNotRfc3986($uri, $field) : [SecurityTxtNotUriReason::NotRfc3986, null];
		}
		if (in_array($scheme, ['http', 'https'], true)) {
			if (in_array($rfc3986->getRawHost(), [null, ''], true)) {
				return [SecurityTxtNotUriReason::HostMissing, null];
			}
			$userInfo = $rfc3986->getRawUserInfo();
			if ($userInfo !== null) {
				// Cut out of the value as written, a URL serialized by a parser would spell the rest the way the parser read it
				$withoutUserInfo = preg_replace('~^(' . self::SCHEME . '://)[^/?#]*@~i', '$1', $uri, 1);
				return [$userInfo === '' ? SecurityTxtNotUriReason::EmptyUserInfo : SecurityTxtNotUriReason::UserInfo, $explain ? $this->suggest($withoutUserInfo) : null];
			}
		}
		$url = Url::parse($uri);
		if ($url === null) {
			if ($rfc3986->getPort() > 65535) {
				return [SecurityTxtNotUriReason::PortOutOfRange, null];
			}
			return [in_array($rfc3986->getRawHost(), [null, ''], true) ? SecurityTxtNotUriReason::HostMissing : SecurityTxtNotUriReason::InvalidHost, null];
		}
		return $url;
	}


	/**
	 * @return array{SecurityTxtNotUriReason, string|null}
	 */
	private function explainNotRfc3986(string $uri, ?SecurityTxtField $field): array
	{
		if (!$this->isSchemeMissing($uri)) {
			return [SecurityTxtNotUriReason::NotRfc3986, null];
		}
		if ($field === SecurityTxtField::Contact) {
			[$reason, $correctValue] = match (true) {
				filter_var($uri, FILTER_VALIDATE_EMAIL) !== false => [SecurityTxtNotUriReason::SchemeMissingEmail, SecurityTxtContact::email($uri)->getUri()],
				preg_match('/^\+?[0-9\-. ]+$/', $uri) === 1 => [SecurityTxtNotUriReason::SchemeMissingPhone, SecurityTxtContact::phone($uri)->getUri()],
				default => [SecurityTxtNotUriReason::SchemeMissingHostname, "https://{$uri}"],
			};
			// Prose with an @ in it does not become a URI by putting a scheme in front, and the hint saying it would goes with the suggestion
			if ($this->suggest($correctValue) !== null) {
				return [$reason, $correctValue];
			}
		}
		return [SecurityTxtNotUriReason::SchemeMissing, null];
	}


	/**
	 * @return Url|array{SecurityTxtNotUriReason, string|null}
	 */
	private function checkFetched(string $uri): Url|array
	{
		return Url::parse($uri) ?? [$this->isSchemeMissing($uri) ? SecurityTxtNotUriReason::SchemeMissing : SecurityTxtNotUriReason::NotUrl, null];
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
