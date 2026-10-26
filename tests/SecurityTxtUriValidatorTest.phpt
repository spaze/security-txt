<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtPolicyNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtPolicyNotUri;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/bootstrap.php';

final class SecurityTxtUriValidatorTest extends TestCase
{

	private SecurityTxtUriValidator $validator;


	public function __construct()
	{
		$this->validator = new SecurityTxtUriValidator();
	}


	/**
	 * An IRI is taken as a URI once the characters RFC 3987 adds are percent-encoded, and only those, not a control character, a private use one or a noncharacter.
	 */
	public function testIriCharacters(): void
	{
		$characters = [
			'U+009F' => "\u{9F}",
			'U+00A0' => "\u{A0}",
			'U+D7FF' => "\u{D7FF}",
			'U+E000' => "\u{E000}",
			'U+F8FF' => "\u{F8FF}",
			'U+F900' => "\u{F900}",
			'U+FDCF' => "\u{FDCF}",
			'U+FDD0' => "\u{FDD0}",
			'U+FDEF' => "\u{FDEF}",
			'U+FDF0' => "\u{FDF0}",
			'U+FFEF' => "\u{FFEF}",
			'U+FFF0' => "\u{FFF0}",
			'U+10000' => "\u{10000}",
			'U+1FFFD' => "\u{1FFFD}",
			'U+1FFFE' => "\u{1FFFE}",
			'U+DFFFD' => "\u{DFFFD}",
			'U+E0000' => "\u{E0000}",
			'U+E0FFF' => "\u{E0FFF}",
			'U+E1000' => "\u{E1000}",
			'U+EFFFD' => "\u{EFFFD}",
			'U+EFFFE' => "\u{EFFFE}",
			'U+F0000' => "\u{F0000}",
			'U+10FFFD' => "\u{10FFFD}",
		];
		$accepted = [];
		foreach ($characters as $name => $character) {
			try {
				$this->validator->validate("https://example.com/{$character}", SecurityTxtPolicyNotUri::class, SecurityTxtPolicyNotHttps::class, SecurityTxtField::Policy);
				$accepted[$name] = true;
			} catch (SecurityTxtError) {
				$accepted[$name] = false;
			}
		}
		Assert::same([
			'U+009F' => false,
			'U+00A0' => true,
			'U+D7FF' => true,
			'U+E000' => false,
			'U+F8FF' => false,
			'U+F900' => true,
			'U+FDCF' => true,
			'U+FDD0' => false,
			'U+FDEF' => false,
			'U+FDF0' => true,
			'U+FFEF' => true,
			'U+FFF0' => false,
			'U+10000' => true,
			'U+1FFFD' => true,
			'U+1FFFE' => false,
			'U+DFFFD' => true,
			'U+E0000' => false,
			'U+E0FFF' => false,
			'U+E1000' => true,
			'U+EFFFD' => true,
			'U+EFFFE' => false,
			'U+F0000' => false,
			'U+10FFFD' => false,
		], $accepted);
	}


	/**
	 * Every refused value says why, and RFC 3986 only when RFC 3986 is what refused it: RFC 3986 allows a URI with no host, a user name or a port of 99999, and those are
	 * refused by RFC 9110, or because the parser this library reads URLs with cannot read them.
	 */
	public function testRefusedValuesSayWhy(): void
	{
		$values = [
			'an email address' => [SecurityTxtField::Contact, 'bar@example.com'],
			'a phone number' => [SecurityTxtField::Contact, '+1-201-555-01234'],
			'a phone number with spaces' => [SecurityTxtField::Contact, '+420 123 456 789'],
			'prose with an email address' => [SecurityTxtField::Contact, 'The security team (security@example.com)'],
			'a hostname' => [SecurityTxtField::Contact, 'example.com'],
			'a Contact with a scheme' => [SecurityTxtField::Contact, 'https://exa mple.com/'],
			'a Contact with an uppercase scheme' => [SecurityTxtField::Contact, 'HTTPS://exa mple.com/'],
			'a Policy with a scheme' => [SecurityTxtField::Policy, 'https://exa mple.com/'],
			'a Policy with a digit and a plus in its scheme' => [SecurityTxtField::Policy, 'web+report2://exa mple.com/'],
			'a Policy with a colon only later' => [SecurityTxtField::Policy, '//exa mple.com:8080/'],
			'a CSAF with a scheme' => [SecurityTxtField::Csaf, 'https://exa mple.com/provider-metadata.json'],
			'a space' => [SecurityTxtField::Policy, 'https://example.com/security policy.html'],
			'a space after the scheme' => [SecurityTxtField::Contact, 'mailto: security@example.com'],
			'a character outside RFC 3987' => [SecurityTxtField::Policy, "https://example.com/\u{FDD0}"],
			'not UTF-8' => [SecurityTxtField::Policy, "https://example.com/\xFF"],
			'three slashes' => [SecurityTxtField::Policy, 'https:///policy'],
			'no slashes' => [SecurityTxtField::Policy, 'https:example.com/policy'],
			'no host after FTP' => [SecurityTxtField::Policy, 'ftp://'],
			'a user name' => [SecurityTxtField::Contact, 'https://security@example.com/'],
			'a user name and a password' => [SecurityTxtField::Policy, 'https://user:secret@example.com/policy'],
			'an @ with no user name' => [SecurityTxtField::Policy, 'https://@example.com/policy'],
			'a user name in an http URI' => [SecurityTxtField::Policy, 'http://user@example.com/policy'],
			'a user name before a dot segment' => [SecurityTxtField::Policy, 'https://user@example.com/a/.?q'],
			'a user name before an internationalized host' => [SecurityTxtField::Policy, 'https://user@xn--khby.example/'],
			'a port out of range' => [SecurityTxtField::Policy, 'https://example.com:65536/'],
			'a host that is not an IPv4 address' => [SecurityTxtField::Policy, 'https://256.0.0.1/'],
			'a host that is not an IPv4 address and the largest port' => [SecurityTxtField::Policy, 'https://256.0.0.1:65535/'],
			'a host that is not a valid A-label' => [SecurityTxtField::Policy, 'https://xn--a.example/'],
			'a percent-encoded space in the host' => [SecurityTxtField::Policy, 'https://exa%20mple.com/'],
			'a file location with a scheme' => [null, 'https://exa mple.com/.well-known/security.txt'],
			'a file location without a scheme' => [null, 'example.com/.well-known/security.txt'],
		];
		$actual = [];
		foreach ($values as $name => [$field, $uri]) {
			$actual[$name] = $this->getRefusal($field, $uri);
		}
		Assert::same([
			'an email address' => [
				"The Contact value (bar@example.com) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'mailto:bar@example.com',
				'The value looks like an email address, add the "mailto" schema',
			],
			'a phone number' => [
				"The Contact value (+1-201-555-01234) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'tel:+1-201-555-01234',
				'The value looks like a phone number, add the "tel" schema',
			],
			'a phone number with spaces' => [
				"The Contact value (+420 123 456 789) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'tel:+420-123-456-789',
				'The value looks like a phone number, add the "tel" scheme and use hyphens instead of the spaces',
			],
			'prose with an email address' => [
				"The Contact value (The security team (security@example.com)) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a hostname' => [
				"The Contact value (example.com) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'https://example.com',
				'The value looks like a hostname, add the "https" schema',
			],
			'a Contact with a scheme' => [
				"The Contact value (https://exa mple.com/) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a Contact with an uppercase scheme' => [
				"The Contact value (HTTPS://exa mple.com/) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a Policy with a scheme' => [
				"The Policy value (https://exa mple.com/) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a Policy with a digit and a plus in its scheme' => [
				"The Policy value (web+report2://exa mple.com/) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a Policy with a colon only later' => [
				"The Policy value (//exa mple.com:8080/) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a CSAF with a scheme' => [
				"The CSAF value (https://exa mple.com/provider-metadata.json) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a space' => [
				"The Policy value (https://example.com/security policy.html) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a space after the scheme' => [
				"The Contact value (mailto: security@example.com) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a character outside RFC 3987' => [
				"The Policy value (https://example.com/%EF%B7%90) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'not UTF-8' => [
				"The Policy value (https://example.com/%FF) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'three slashes' => [
				'The Policy value (https:///policy) has no host',
				null,
				'Put // and the host right after the scheme',
			],
			'no slashes' => [
				'The Policy value (https:example.com/policy) has no host',
				null,
				'Put // and the host right after the scheme',
			],
			'no host after FTP' => [
				'The Policy value (ftp://) has no host',
				null,
				'Put // and the host right after the scheme',
			],
			'a user name' => [
				"The Contact value (https://security@example.com/) contains a user name or a password, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
				'https://example.com/',
				'Remove the user name, the password, and the @ after them',
			],
			'a user name and a password' => [
				"The Policy value (https://user:secret@example.com/policy) contains a user name or a password, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
				'https://example.com/policy',
				'Remove the user name, the password, and the @ after them',
			],
			'an @ with no user name' => [
				"The Policy value (https://@example.com/policy) has an @ before the host, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
				'https://example.com/policy',
				'Remove the @',
			],
			// Not suggested, the field refuses `http` next
			'a user name in an http URI' => [
				"The Policy value (http://user@example.com/policy) contains a user name or a password, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
				null,
				'Remove the user name, the password, and the @ after them',
			],
			// Cut out of the value as written, PHP before 8.5.12 reads the query as a path segment
			'a user name before a dot segment' => [
				"The Policy value (https://user@example.com/a/.?q) contains a user name or a password, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
				'https://example.com/a/.?q',
				'Remove the user name, the password, and the @ after them',
			],
			// And not decoded to a host that encodes back as `xn--jgb`
			'a user name before an internationalized host' => [
				"The Policy value (https://user@xn--khby.example/) contains a user name or a password, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
				'https://xn--khby.example/',
				'Remove the user name, the password, and the @ after them',
			],
			'a port out of range' => [
				'The Policy value (https://example.com:65536/) has a port above 65535',
				null,
				'Use a port number from 0 to 65535, or leave the port out',
			],
			'a host that is not an IPv4 address' => [
				"The Policy value (https://256.0.0.1/) has a host that isn't a valid domain name or IP address",
				null,
				'Use a domain name or an IP address as the host',
			],
			'a host that is not an IPv4 address and the largest port' => [
				"The Policy value (https://256.0.0.1:65535/) has a host that isn't a valid domain name or IP address",
				null,
				'Use a domain name or an IP address as the host',
			],
			'a host that is not a valid A-label' => [
				"The Policy value (https://xn--a.example/) has a host that isn't a valid domain name or IP address",
				null,
				'Use a domain name or an IP address as the host',
			],
			'a percent-encoded space in the host' => [
				"The Policy value (https://exa%20mple.com/) has a host that isn't a valid domain name or IP address",
				null,
				'Use a domain name or an IP address as the host',
			],
			'a file location with a scheme' => [
				"The location of the file https://exa mple.com/.well-known/security.txt can't be parsed as a URL",
				null,
				'Use a URL as the value',
			],
			'a file location without a scheme' => [
				"The location of the file example.com/.well-known/security.txt doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
		], $actual);
	}


	/**
	 * @return array{string, string|null, string}
	 */
	private function getRefusal(?SecurityTxtField $field, string $uri): array
	{
		[$notUri, $notHttps] = match ($field) {
			null => [SecurityTxtFileLocationNotUri::class, SecurityTxtFileLocationNotHttps::class],
			SecurityTxtField::Contact => [SecurityTxtContactNotUri::class, SecurityTxtContactNotHttps::class],
			SecurityTxtField::Csaf => [SecurityTxtCsafNotUri::class, SecurityTxtCsafNotHttps::class],
			default => [SecurityTxtPolicyNotUri::class, SecurityTxtPolicyNotHttps::class],
		};
		$e = Assert::throws(function () use ($uri, $notUri, $notHttps, $field): void {
			$this->validator->validate($uri, $notUri, $notHttps, $field, $field === null);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		$violation = $e->getViolation();
		Assert::type($notUri, $violation);
		$correctValue = $violation->getCorrectValue();
		return [$violation->getMessage(), $correctValue === null ? null : new SecurityTxtPrintableValue($correctValue)->render(), $violation->getHowToFix()];
	}

}

new SecurityTxtUriValidatorTest()->run();
