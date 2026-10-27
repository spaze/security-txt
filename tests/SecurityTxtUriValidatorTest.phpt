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
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotUri;
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
			'a hostname and a path' => [SecurityTxtField::Contact, 'example.com/security'],
			'a hostname and a full stop' => [SecurityTxtField::Contact, 'example.com.'],
			'a hostname and a comma' => [SecurityTxtField::Contact, 'example.com,'],
			'an internationalized hostname, a port and a path' => [SecurityTxtField::Contact, "h\u{E1}\u{10D}ky.example:8443/"],
			'an uppercase A-label' => [SecurityTxtField::Contact, 'XN--HKY-SLA3E.EXAMPLE'],
			'a hostname, a path and a full stop' => [SecurityTxtField::Contact, 'example.com/security.'],
			'a hostname, a path, a comma and an email address' => [SecurityTxtField::Contact, 'example.com/security,security@example.com'],
			'a wildcard' => [SecurityTxtField::Contact, '*.example.com'],
			'a hostname and a closing bracket' => [SecurityTxtField::Contact, 'example.com)'],
			'hyphens and a dot' => [SecurityTxtField::Contact, '-.-'],
			'a slash' => [SecurityTxtField::Contact, 'N/A'],
			'a phone number with dots' => [SecurityTxtField::Contact, '555.123.4567'],
			'a word' => [SecurityTxtField::Contact, 'TODO'],
			'hyphens' => [SecurityTxtField::Contact, '---'],
			'prose' => [SecurityTxtField::Contact, 'the security team'],
			'a fingerprint' => [SecurityTxtField::Encryption, '5F2DE5521C63A801AB59CCB603D49DE44B29100F'],
			'a fingerprint as GnuPG prints it' => [SecurityTxtField::Encryption, '5F2D E552 1C63 A801 AB59  CCB6 03D4 9DE4 4B29 100F'],
			'a fingerprint one digit short' => [SecurityTxtField::Encryption, '5F2DE5521C63A801AB59CCB603D49DE44B29100'],
			'a fingerprint in a Policy' => [SecurityTxtField::Policy, '5F2DE5521C63A801AB59CCB603D49DE44B29100F'],
			'a fingerprint and a newline' => [SecurityTxtField::Encryption, "5F2DE5521C63A801AB59CCB603D49DE44B29100F\n"],
			'a fingerprint with spaces after the scheme' => [SecurityTxtField::Encryption, 'openpgp4fpr:5F2D E552 1C63 A801 AB59  CCB6 03D4 9DE4 4B29 100F'],
			'a fingerprint after the scheme and a space' => [SecurityTxtField::Encryption, 'openpgp4fpr: 5F2DE5521C63A801AB59CCB603D49DE44B29100F'],
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
			'more than one URI' => [SecurityTxtField::Hiring, 'https://example.com/jobs, https://example.net/jobs'],
			'more than one URI separated by a control character' => [SecurityTxtField::Policy, "https://a.example/\x01https://b.example/"],
			'a word with a colon after a space' => [SecurityTxtField::Contact, 'mailto:security@example.com?subject=Security report:XSS'],
			'a phone number after tel: with spaces' => [SecurityTxtField::Contact, 'tel:+420 123 456 789'],
			'a phone number with a space after tel: and more' => [SecurityTxtField::Contact, 'tel: +420 123 456 789'],
			'a phone number with only a space after tel:' => [SecurityTxtField::Contact, 'tel: +420123456789'],
			'a phone number and more' => [SecurityTxtField::Contact, 'tel:+420 123 456 789 (office)'],
			'hyphens and spaces after tel:' => [SecurityTxtField::Contact, 'tel:- -'],
			'a label before an email address' => [SecurityTxtField::Contact, 'Email: security@example.com'],
			'more than one email address' => [SecurityTxtField::Contact, 'security@example.com, abuse@example.com'],
			'an email address in prose in a Policy' => [SecurityTxtField::Policy, 'Write to security@example.com'],
			'an email address and a URI' => [SecurityTxtField::Contact, 'security@example.com, https://example.com/report'],
			'an email address and a mailto URI' => [SecurityTxtField::Contact, 'security@example.com, mailto:abuse@example.com'],
			'a label, an email address and a SIP URI' => [SecurityTxtField::Contact, 'Email: security@example.com, sip:abuse@example.com'],
			'a label, an email address and a phone number' => [SecurityTxtField::Contact, 'Email: security@example.com, +1-201-555-0123'],
			'a phone number with spaces and a URI after a semicolon' => [SecurityTxtField::Contact, '+420 123 456 789; mailto:security@example.com'],
			'a phone number and one after a label' => [SecurityTxtField::Contact, '+420 123 456 789, Phone: +1-201-555-0123'],
			'an email address and six digits' => [SecurityTxtField::Contact, '<security@example.com>, 123 456'],
			'an email address and seven digits' => [SecurityTxtField::Contact, '<security@example.com>, 555 1234'],
			'text and a phone number after a space after the scheme' => [SecurityTxtField::Contact, 'Call us, TEL: +420 123 456 789'],
			'an email address and a phone number with brackets' => [SecurityTxtField::Contact, 'Email: security@example.com, +44 (0)20 7946 0958'],
			'a phone number with brackets first and a URI' => [SecurityTxtField::Contact, '(201) 555-0123, mailto:security@example.com'],
			'an email address and a phone number with dots after a tab and a label' => [SecurityTxtField::Contact, "<security@example.com>,\tTel.: 201.555.0123"],
			'an email address and a phone number right after a label' => [SecurityTxtField::Contact, 'Email: security@example.com, Tel/Fax:+1-201-555-0123'],
			'an email address and a phone number after a label that is not ASCII' => [SecurityTxtField::Contact, "<security@example.com>, \u{422}\u{435}\u{43B}.: +7 495 123-45-67"],
			'a URI and a phone number' => [SecurityTxtField::Contact, 'https://example.com/report, +1-201-555-0123'],
			'text, a URI and a phone number' => [SecurityTxtField::Contact, 'Report at https://example.com/report, +1-201-555-0123'],
			'a phone number and an email address after a comma with no space' => [SecurityTxtField::Contact, '+1-201-555-0123,<security@example.com>'],
			'an email address and a phone number with more spaces' => [SecurityTxtField::Contact, 'Email: security@example.com, +1 - 201 - 555 - 0123'],
			'an email address and a number in a sentence' => [SecurityTxtField::Contact, '<security@example.com>, 1234567 visits'],
			'an email address and a phone number after a label like a scheme' => [SecurityTxtField::Contact, '<security@example.com>, Telephone: +1-201-555-0123'],
			'a phone number and a space before a semicolon' => [SecurityTxtField::Contact, '+1-201-555-0123 ; <security@example.com>'],
			'a phone number and a URI in a Policy' => [SecurityTxtField::Policy, '+1-201-555-0123, https://example.com/report'],
			'text and digits at the end of a URI' => [SecurityTxtField::Contact, 'Report at https://example.com/report?id=1234567'],
			'a label and digits after a comma in a URI' => [SecurityTxtField::Contact, 'Report: https://example.com/report?ids=1234567,7654321'],
			'a URI and an email address' => [SecurityTxtField::Contact, 'https://example.com/report, security@example.com'],
			'a mailto URI and an email address' => [SecurityTxtField::Contact, 'mailto:security@example.com, abuse@example.com'],
			'a name in a mailto URI' => [SecurityTxtField::Contact, 'mailto:Security Team <security@example.com>'],
			'a space after the scheme and an email address' => [SecurityTxtField::Contact, 'tel: +420-123-456-789, <security@example.com>'],
			'an uppercase scheme, a space and an email address' => [SecurityTxtField::Contact, 'TEL: +420-123-456-789, <security@example.com>'],
			'a space after the scheme and a URI' => [SecurityTxtField::Contact, 'mailto: security@example.com, https://example.com/report'],
			'a comma and a space in a URI' => [SecurityTxtField::Contact, 'https://example.com/a,b c/security@example.com'],
			'a URI and an email address after a semicolon' => [SecurityTxtField::Contact, 'https://example.com/report; security@example.com'],
			'a label and a space after the scheme' => [SecurityTxtField::Contact, 'Email: mailto: security@example.com'],
			'an email address and a space after the scheme' => [SecurityTxtField::Contact, '<security@example.com>, tel: +420-123-456-789'],
			'a label like a scheme before a URI' => [SecurityTxtField::Policy, 'HTTPS: https://example.com/policy'],
			'an email address and a scheme with nothing after it' => [SecurityTxtField::Contact, 'security@example.com, tel:'],
			'two openpgp4fpr URIs' => [SecurityTxtField::Policy, 'openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F openpgp4fpr:6F2DE5521C63A801AB59CCB603D49DE44B29100F'],
			'an address split by a space' => [SecurityTxtField::Contact, 'security team@example.com'],
			'a scheme split by a space' => [SecurityTxtField::Policy, 'htt ps://example.com/policy'],
			'text before the URI and a full stop' => [SecurityTxtField::Contact, 'Please report at https://example.com/security.'],
			'text in parentheses' => [SecurityTxtField::Policy, '(see https://example.com/policy)'],
			'two URIs in angle brackets' => [SecurityTxtField::Policy, '<https://a.example/> <https://b.example/>'],
			'a URI in quotes' => [SecurityTxtField::Policy, '"https://example.com/policy"'],
			'a URI in square brackets' => [SecurityTxtField::Policy, '[https://example.com/policy]'],
			'a URI in parentheses' => [SecurityTxtField::Contact, '(https://example.com/report)'],
			'a label before a phone number' => [SecurityTxtField::Contact, 'Phone: +420 123 456 789'],
			'a label before a URI and a note' => [SecurityTxtField::Policy, 'Policy: https://example.com/policy (English)'],
			'a label before a value' => [SecurityTxtField::Policy, 'Policy: dns:example.com'],
			'a label before an email address in a Policy' => [SecurityTxtField::Policy, 'Email: security@example.com'],
			'a label and a control character before an address' => [SecurityTxtField::Contact, "Email:\x01security@example.com"],
			'text before an FTP URI' => [SecurityTxtField::Policy, 'see: ftp://example.com/policy'],
			'text before the URI and a closing bracket' => [SecurityTxtField::Contact, 'Report it (at https://example.com/security)'],
			'an address and a semicolon' => [SecurityTxtField::Contact, 'security@example.com;'],
			'a label before a URN' => [SecurityTxtField::Policy, 'Note: urn:isbn:0451450523'],
			'nothing' => [SecurityTxtField::Policy, ''],
			'a URI in angle brackets' => [SecurityTxtField::Policy, '<https://example.com/policy>'],
			'an email address in angle brackets' => [SecurityTxtField::Contact, '<security@example.com>'],
			'text before the URI' => [SecurityTxtField::Contact, 'Report at https://example.com/report'],
			'a label before the URI' => [SecurityTxtField::Policy, 'URL: https://example.com/policy'],
			'a host and a port after a space' => [SecurityTxtField::Policy, 'https:// example.com:8443/policy'],
			'a space in the port' => [SecurityTxtField::Policy, 'https://example.com: 8080/policy'],
			'a tab after the scheme' => [SecurityTxtField::Contact, "mailto:\tsecurity@example.com"],
			'a C1 control character' => [SecurityTxtField::Policy, "https://example.com/\u{85}policy"],
			'a control character between two labels' => [SecurityTxtField::Policy, "https://example.com\x01.evil.example/"],
			'a stray percent sign' => [SecurityTxtField::Policy, 'https://example.com/100%'],
			'a stray percent sign and more' => [SecurityTxtField::Policy, 'https://example.com/100%|'],
			'a stray percent sign in the host' => [SecurityTxtField::Policy, 'https://exa%mple.com/'],
			'an uppercase percent-encoded character and more' => [SecurityTxtField::Policy, 'https://example.com/a%2Fb|'],
			'a backslash' => [SecurityTxtField::Policy, 'https://example.com\policy'],
			'a bracket outside the host' => [SecurityTxtField::Policy, 'https://[2001:db8::1]/a[b]'],
			'a second number sign' => [SecurityTxtField::Policy, 'https://example.com/#a#b'],
			'an IPv6 address without brackets' => [SecurityTxtField::Policy, 'https://2001:db8::1/policy'],
			'a port that is not a number' => [SecurityTxtField::Policy, 'https://example.com:80a/'],
			'an IPv6 address and a port that is not a number' => [SecurityTxtField::Policy, 'https://[2001:db8::1]:80a/'],
			'a note after a URI with no path' => [SecurityTxtField::Policy, 'https://example.com (preferred)'],
			'a note after a URI with a port and no path' => [SecurityTxtField::Policy, 'https://example.com:8080 (alt)'],
			'a space after the dns scheme' => [SecurityTxtField::Policy, 'dns: example.com'],
			'an openpgp4fpr URI and another URI' => [SecurityTxtField::Policy, 'openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F https://example.com/key.asc'],
			'a delete character' => [SecurityTxtField::Policy, "https://example.com/\x7fpolicy"],
			'a control character before a slash' => [SecurityTxtField::Policy, "https://example.com\x01/policy"],
			'two control characters before a slash' => [SecurityTxtField::Policy, "https://example.com\x01\x01/policy"],
			'two control characters after a slash' => [SecurityTxtField::Policy, "https://example.com/\x01\x01policy"],
			'control characters at the end' => [SecurityTxtField::Policy, "https://example.com/policy\x01\x01\x01"],
			'a valid escape in the host and a stray percent sign' => [SecurityTxtField::Policy, 'https://exa%41mple.com/100%'],
			'an unclosed IPv6 address' => [SecurityTxtField::Policy, 'https://[2001:db8::1/policy'],
			'text after an IPv6 address' => [SecurityTxtField::Policy, 'https://[2001:db8::1]x/'],
			'two @ before an IPv6 address' => [SecurityTxtField::Policy, 'foo://a@b@[::1]/'],
			'a character in the host' => [SecurityTxtField::Policy, 'https://exa|mple.com/'],
			'a character in the port' => [SecurityTxtField::Policy, 'https://example.com:80|80/'],
			'an IRI with a character to percent-encode' => [SecurityTxtField::Policy, "https://h\u{E1}\u{10D}ky.example/a|b"],
			'a tilde and a character to percent-encode' => [SecurityTxtField::Policy, 'https://example.com/~user/a|b'],
			'a number sign in a value refused for something else' => [SecurityTxtField::Policy, 'https://example.com:8080:8443/#top'],
			'an IPv6 address without brackets and a group like a port' => [SecurityTxtField::Policy, 'https://2001:db8::1:8080/policy'],
			'an IPv6 address without brackets and a short last group' => [SecurityTxtField::Policy, 'https://fe80::1:4/'],
			'an IPv6 address without brackets and a port' => [SecurityTxtField::Policy, 'https://2001:db8:1:2:3:4:5:6:8080/policy'],
			'an IPv6 address without brackets and a port too large for a group' => [SecurityTxtField::Policy, 'https://2001:db8::1:65000/policy'],
			'an IPv6 address without brackets in an http URI' => [SecurityTxtField::Policy, 'http://2001:db8::1/policy'],
			'an IPv6 address without brackets and a hexadecimal last group in an http URI' => [SecurityTxtField::Policy, 'http://2001:db8::ff/policy'],
			'a user name and an IPv6 address without brackets' => [SecurityTxtField::Policy, 'https://user@2001:db8::ff/policy'],
			'an IPv6 address and a zone without brackets' => [SecurityTxtField::Policy, 'https://fe80::1%25eth0/policy'],
			'an IPv6 address without brackets and a character' => [SecurityTxtField::Policy, 'https://2001:db8::1|/policy'],
			'two ports' => [SecurityTxtField::Policy, 'https://example.com:8080:8443/'],
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
				'The value looks like an email address, add the "mailto" scheme',
			],
			'a phone number' => [
				"The Contact value (+1-201-555-01234) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'tel:+1-201-555-01234',
				'The value looks like a phone number, add the "tel" scheme',
			],
			'a phone number with spaces' => [
				"The Contact value (+420 123 456 789) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'tel:+420-123-456-789',
				'The value looks like a phone number, add the "tel" scheme and use hyphens instead of the spaces',
			],
			'prose with an email address' => [
				'The Contact value (The security team (security@example.com)) has text around the email address',
				'mailto:security@example.com',
				'Use just the email address, with the "mailto" scheme',
			],
			'a hostname' => [
				"The Contact value (example.com) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'https://example.com',
				'The value looks like a hostname, add the "https" scheme',
			],
			'a hostname and a path' => [
				"The Contact value (example.com/security) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'https://example.com/security',
				'The value looks like a hostname, add the "https" scheme',
			],
			// Not `https://example.com.`, the dot more likely ends a sentence
			'a hostname and a full stop' => [
				"The Contact value (example.com.) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			// Not `https://example.com,`
			'a hostname and a comma' => [
				"The Contact value (example.com,) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'an internationalized hostname, a port and a path' => [
				"The Contact value (h%C3%A1%C4%8Dky.example:8443/) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				"https://h\u{E1}\u{10D}ky.example:8443/",
				'The value looks like a hostname, add the "https" scheme',
			],
			'an uppercase A-label' => [
				"The Contact value (XN--HKY-SLA3E.EXAMPLE) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'https://XN--HKY-SLA3E.EXAMPLE',
				'The value looks like a hostname, add the "https" scheme',
			],
			'a hostname, a path and a full stop' => [
				"The Contact value (example.com/security.) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			// Not `https://example.com/security,security@example.com`, which would leave out the email address
			'a hostname, a path, a comma and an email address' => [
				"The Contact value (example.com/security,security@example.com) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a wildcard' => [
				"The Contact value (*.example.com) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a hostname and a closing bracket' => [
				"The Contact value (example.com)) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'hyphens and a dot' => [
				"The Contact value (-.-) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a slash' => [
				"The Contact value (N/A) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			// Not `https://555.123.4567`
			'a phone number with dots' => [
				"The Contact value (555.123.4567) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'tel:555.123.4567',
				'The value looks like a phone number, add the "tel" scheme',
			],
			// Not `https://TODO`, a hostname has two labels or more
			'a word' => [
				"The Contact value (TODO) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			// Not `tel:---`, a phone number has a digit
			'hyphens' => [
				"The Contact value (---) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			// Not `https://the security team`, which is no URI either
			'prose' => [
				"The Contact value (the security team) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a fingerprint' => [
				"The Encryption value (5F2DE5521C63A801AB59CCB603D49DE44B29100F) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F',
				'The value looks like an OpenPGP key fingerprint, add the "openpgp4fpr" scheme',
			],
			'a fingerprint as GnuPG prints it' => [
				"The Encryption value (5F2D E552 1C63 A801 AB59  CCB6 03D4 9DE4 4B29 100F) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				'openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F',
				'The value looks like an OpenPGP key fingerprint, add the "openpgp4fpr" scheme and remove the spaces',
			],
			'a fingerprint one digit short' => [
				"The Encryption value (5F2DE5521C63A801AB59CCB603D49DE44B29100) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a fingerprint in a Policy' => [
				"The Policy value (5F2DE5521C63A801AB59CCB603D49DE44B29100F) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			// The newline is a control character, not a fingerprint's
			'a fingerprint and a newline' => [
				"The Encryption value (5F2DE5521C63A801AB59CCB603D49DE44B29100F%0A) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a fingerprint with spaces after the scheme' => [
				"The Encryption value (openpgp4fpr:5F2D E552 1C63 A801 AB59  CCB6 03D4 9DE4 4B29 100F) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				'openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F',
				'Remove the spaces from the fingerprint',
			],
			'a fingerprint after the scheme and a space' => [
				"The Encryption value (openpgp4fpr: 5F2DE5521C63A801AB59CCB603D49DE44B29100F) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				'openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F',
				'Remove the space after the scheme',
			],
			'a Contact with a scheme' => [
				"The Contact value (https://exa mple.com/) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces from the host',
			],
			'a Contact with an uppercase scheme' => [
				"The Contact value (HTTPS://exa mple.com/) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces from the host',
			],
			'a Policy with a scheme' => [
				"The Policy value (https://exa mple.com/) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces from the host',
			],
			'a Policy with a digit and a plus in its scheme' => [
				"The Policy value (web+report2://exa mple.com/) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces from the host',
			],
			'a Policy with a colon only later' => [
				"The Policy value (//exa mple.com:8080/) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a CSAF with a scheme' => [
				"The CSAF value (https://exa mple.com/provider-metadata.json) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces from the host',
			],
			'a space' => [
				"The Policy value (https://example.com/security policy.html) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			'a space after the scheme' => [
				"The Contact value (mailto: security@example.com) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				'mailto:security@example.com',
				'Remove the space after the scheme',
			],
			'a character outside RFC 3987' => [
				"The Policy value (https://example.com/%EF%B7%90) doesn't follow the URI syntax described in RFC 3986, it contains a character that has to be percent-encoded",
				null,
				'Percent-encode the character',
			],
			'not UTF-8' => [
				"The Policy value (https://example.com/%FF) doesn't follow the URI syntax described in RFC 3986, it contains a character that has to be percent-encoded",
				null,
				'Percent-encode the character',
			],
			'more than one URI' => [
				'The Hiring value (https://example.com/jobs, https://example.net/jobs) lists more than one URI',
				null,
				'Put each URI in a field of its own',
			],
			'more than one URI separated by a control character' => [
				'The Policy value (https://a.example/%01https://b.example/) lists more than one URI',
				null,
				'Put each URI in a field of its own',
			],
			'a word with a colon after a space' => [
				"The Contact value (mailto:security@example.com?subject=Security report:XSS) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			'a phone number after tel: with spaces' => [
				"The Contact value (tel:+420 123 456 789) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				'tel:+420-123-456-789',
				'Use hyphens instead of the spaces',
			],
			'a phone number with a space after tel: and more' => [
				"The Contact value (tel: +420 123 456 789) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				'tel:+420-123-456-789',
				'Remove the space after the scheme, and use hyphens instead of the other spaces',
			],
			'a phone number with only a space after tel:' => [
				"The Contact value (tel: +420123456789) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				'tel:+420123456789',
				'Remove the space after the scheme',
			],
			'a phone number and more' => [
				"The Contact value (tel:+420 123 456 789 (office)) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			// Not `tel:---`
			'hyphens and spaces after tel:' => [
				"The Contact value (tel:- -) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			'a label before an email address' => [
				'The Contact value (Email: security@example.com) has text around the email address',
				'mailto:security@example.com',
				'Use just the email address, with the "mailto" scheme',
			],
			'more than one email address' => [
				'The Contact value (security@example.com, abuse@example.com) lists more than one email address',
				null,
				'Put each email address in a Contact field of its own, with the "mailto" scheme',
			],
			// Only a Contact is an email address
			'an email address in prose in a Policy' => [
				"The Policy value (Write to security@example.com) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'an email address and a URI' => [
				'The Contact value (security@example.com, https://example.com/report) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'an email address and a mailto URI' => [
				'The Contact value (security@example.com, mailto:abuse@example.com) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// Not `mailto:security@example.com`, which would leave out the SIP URI
			'a label, an email address and a SIP URI' => [
				'The Contact value (Email: security@example.com, sip:abuse@example.com) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// Nor the phone number
			'a label, an email address and a phone number' => [
				'The Contact value (Email: security@example.com, +1-201-555-0123) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a phone number with spaces and a URI after a semicolon' => [
				'The Contact value (+420 123 456 789; mailto:security@example.com) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a phone number and one after a label' => [
				'The Contact value (+420 123 456 789, Phone: +1-201-555-0123) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// Too few digits for a phone number
			'an email address and six digits' => [
				'The Contact value (<security@example.com>, 123 456) has text around the email address',
				'mailto:security@example.com',
				'Use just the email address, with the "mailto" scheme',
			],
			'an email address and seven digits' => [
				'The Contact value (<security@example.com>, 555 1234) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// The number is the `tel:` one, not one more
			'text and a phone number after a space after the scheme' => [
				"The Contact value (Call us, TEL: +420 123 456 789) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'an email address and a phone number with brackets' => [
				'The Contact value (Email: security@example.com, +44 (0)20 7946 0958) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a phone number with brackets first and a URI' => [
				'The Contact value ((201) 555-0123, mailto:security@example.com) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'an email address and a phone number with dots after a tab and a label' => [
				"The Contact value (<security@example.com>,\u{2192}Tel.: 201.555.0123) lists more than one contact",
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'an email address and a phone number right after a label' => [
				'The Contact value (Email: security@example.com, Tel/Fax:+1-201-555-0123) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'an email address and a phone number after a label that is not ASCII' => [
				'The Contact value (<security@example.com>, %D0%A2%D0%B5%D0%BB.: +7 495 123-45-67) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a URI and a phone number' => [
				'The Contact value (https://example.com/report, +1-201-555-0123) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// The comma after the URI separates it from the phone number
			'text, a URI and a phone number' => [
				'The Contact value (Report at https://example.com/report, +1-201-555-0123) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a phone number and an email address after a comma with no space' => [
				'The Contact value (+1-201-555-0123,<security@example.com>) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'an email address and a phone number with more spaces' => [
				'The Contact value (Email: security@example.com, +1 - 201 - 555 - 0123) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// A number with words after it is no phone number
			'an email address and a number in a sentence' => [
				'The Contact value (<security@example.com>, 1234567 visits) has text around the email address',
				'mailto:security@example.com',
				'Use just the email address, with the "mailto" scheme',
			],
			// `Telephone` is no `tel`
			'an email address and a phone number after a label like a scheme' => [
				'The Contact value (<security@example.com>, Telephone: +1-201-555-0123) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a phone number and a space before a semicolon' => [
				'The Contact value (+1-201-555-0123 ; <security@example.com>) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// Only a Contact is a phone number
			'a phone number and a URI in a Policy' => [
				'The Policy value (+1-201-555-0123, https://example.com/report) has text before the URI',
				'https://example.com/report',
				'Remove the text, leave just the URI',
			],
			// Digits in the URI are no phone number
			'text and digits at the end of a URI' => [
				'The Contact value (Report at https://example.com/report?id=1234567) has text before the URI',
				'https://example.com/report?id=1234567',
				'Remove the text, leave just the URI',
			],
			'a label and digits after a comma in a URI' => [
				'The Contact value (Report: https://example.com/report?ids=1234567,7654321) starts with a label',
				'https://example.com/report?ids=1234567,7654321',
				'Remove the label, leave just the value',
			],
			'a URI and an email address' => [
				'The Contact value (https://example.com/report, security@example.com) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a mailto URI and an email address' => [
				'The Contact value (mailto:security@example.com, abuse@example.com) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// After a scheme only a comma ends the URI
			'a name in a mailto URI' => [
				"The Contact value (mailto:Security Team <security@example.com>) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			// Not `mailto:security@example.com`, which would leave out the phone number
			'a space after the scheme and an email address' => [
				'The Contact value (tel: +420-123-456-789, <security@example.com>) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'an uppercase scheme, a space and an email address' => [
				'The Contact value (TEL: +420-123-456-789, <security@example.com>) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			// Not `https://example.com/report`, which would leave out the email address
			'a space after the scheme and a URI' => [
				'The Contact value (mailto: security@example.com, https://example.com/report) lists more than one URI',
				null,
				'Put each URI in a field of its own',
			],
			// A comma without a space after it is in the URI
			'a comma and a space in a URI' => [
				"The Contact value (https://example.com/a,b c/security@example.com) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			'a URI and an email address after a semicolon' => [
				'The Contact value (https://example.com/report; security@example.com) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a label and a space after the scheme' => [
				'The Contact value (Email: mailto: security@example.com) has text around the email address',
				'mailto:security@example.com',
				'Use just the email address, with the "mailto" scheme',
			],
			// Not `mailto:security@example.com`, which would leave out the phone number
			'an email address and a space after the scheme' => [
				'The Contact value (<security@example.com>, tel: +420-123-456-789) lists more than one contact',
				null,
				'Put each in a Contact field of its own, with the "mailto" or "tel" scheme where it has none',
			],
			'a label like a scheme before a URI' => [
				'The Policy value (HTTPS: https://example.com/policy) has text before the URI',
				'https://example.com/policy',
				'Remove the text, leave just the URI',
			],
			'an email address and a scheme with nothing after it' => [
				"The Contact value (security@example.com, tel:) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'two openpgp4fpr URIs' => [
				'The Policy value (openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F openpgp4fpr:6F2DE5521C63A801AB59CCB603D49DE44B29100F) lists more than one URI',
				null,
				'Put each URI in a field of its own',
			],
			'an address split by a space' => [
				"The Contact value (security team@example.com) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a scheme split by a space' => [
				"The Policy value (htt ps://example.com/policy) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'text before the URI and a full stop' => [
				'The Contact value (Please report at https://example.com/security.) has text before the URI',
				null,
				'Remove the text, leave just the URI',
			],
			'text in parentheses' => [
				'The Policy value ((see https://example.com/policy)) is in parentheses',
				null,
				'Remove the parentheses',
			],
			'two URIs in angle brackets' => [
				'The Policy value (<https://a.example/> <https://b.example/>) lists more than one URI',
				null,
				'Put each URI in a field of its own',
			],
			'a URI in quotes' => [
				'The Policy value ("https://example.com/policy") is in quotes',
				'https://example.com/policy',
				'Remove the quotes',
			],
			'a URI in square brackets' => [
				'The Policy value ([https://example.com/policy]) is in square brackets',
				'https://example.com/policy',
				'Remove the square brackets',
			],
			'a URI in parentheses' => [
				'The Contact value ((https://example.com/report)) is in parentheses',
				'https://example.com/report',
				'Remove the parentheses',
			],
			'a label before a phone number' => [
				'The Contact value (Phone: +420 123 456 789) starts with a label',
				null,
				'Remove the label, leave just the value',
			],
			'a label before a URI and a note' => [
				'The Policy value (Policy: https://example.com/policy (English)) starts with a label',
				null,
				'Remove the label, leave just the value',
			],
			'a label before a value' => [
				'The Policy value (Policy: dns:example.com) has text before the URI',
				'dns:example.com',
				'Remove the text, leave just the URI',
			],
			'a label before an email address in a Policy' => [
				'The Policy value (Email: security@example.com) starts with a label',
				null,
				'Remove the label, leave just the value',
			],
			// A control character is no separator of addresses
			'a label and a control character before an address' => [
				'The Contact value (Email:%01security@example.com) starts with a label',
				null,
				'Remove the label, leave just the value',
			],
			'text before an FTP URI' => [
				'The Policy value (see: ftp://example.com/policy) has text before the URI',
				'ftp://example.com/policy',
				'Remove the text, leave just the URI',
			],
			'text before the URI and a closing bracket' => [
				'The Contact value (Report it (at https://example.com/security)) has text before the URI',
				null,
				'Remove the text, leave just the URI',
			],
			'an address and a semicolon' => [
				"The Contact value (security@example.com;) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
				null,
				'Use a URI as the value',
			],
			'a label before a URN' => [
				'The Policy value (Note: urn:isbn:0451450523) starts with a label',
				'urn:isbn:0451450523',
				'Remove the label, leave just the value',
			],
			'nothing' => [
				'The Policy value () is empty',
				null,
				'Use a URI as the value',
			],
			'a URI in angle brackets' => [
				'The Policy value (<https://example.com/policy>) is in angle brackets',
				'https://example.com/policy',
				'Remove the angle brackets',
			],
			'an email address in angle brackets' => [
				'The Contact value (<security@example.com>) is in angle brackets',
				null,
				'Remove the angle brackets',
			],
			'text before the URI' => [
				'The Contact value (Report at https://example.com/report) has text before the URI',
				'https://example.com/report',
				'Remove the text, leave just the URI',
			],
			'a label before the URI' => [
				'The Policy value (URL: https://example.com/policy) has text before the URI',
				'https://example.com/policy',
				'Remove the text, leave just the URI',
			],
			'a host and a port after a space' => [
				"The Policy value (https:// example.com:8443/policy) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces from the host',
			],
			'a space in the port' => [
				"The Policy value (https://example.com: 8080/policy) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces from the port',
			],
			'a tab after the scheme' => [
				"The Contact value (mailto:\u{2192}security@example.com) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				'mailto:security@example.com',
				'Remove the control characters',
			],
			'a C1 control character' => [
				"The Policy value (https://example.com/%C2%85policy) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				'https://example.com/policy',
				'Remove the control characters',
			],
			'a control character between two labels' => [
				"The Policy value (https://example.com%01.evil.example/) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				null,
				'Remove the control characters',
			],
			'a stray percent sign' => [
				"The Policy value (https://example.com/100%) doesn't follow the URI syntax described in RFC 3986, it contains a % not followed by two hexadecimal digits",
				'https://example.com/100%25',
				'Percent-encode the % itself, as %25',
			],
			'a stray percent sign and more' => [
				"The Policy value (https://example.com/100%|) doesn't follow the URI syntax described in RFC 3986, it contains a % not followed by two hexadecimal digits",
				null,
				'Percent-encode the % itself, as %25',
			],
			'a stray percent sign in the host' => [
				"The Policy value (https://exa%mple.com/) doesn't follow the URI syntax described in RFC 3986, it contains a % not followed by two hexadecimal digits",
				null,
				'Remove the % from the host',
			],
			'an uppercase percent-encoded character and more' => [
				"The Policy value (https://example.com/a%2Fb|) doesn't follow the URI syntax described in RFC 3986, it contains |, which has to be percent-encoded",
				null,
				'Percent-encode it as %7C',
			],
			'a backslash' => [
				"The Policy value (https://example.com\\policy) doesn't follow the URI syntax described in RFC 3986, it contains a backslash",
				null,
				'Use a slash instead, or percent-encode the backslash as %5C',
			],
			'a bracket outside the host' => [
				"The Policy value (https://[2001:db8::1]/a[b]) doesn't follow the URI syntax described in RFC 3986, it contains [, which has to be percent-encoded",
				null,
				'Percent-encode it as %5B',
			],
			'a second number sign' => [
				"The Policy value (https://example.com/#a#b) doesn't follow the URI syntax described in RFC 3986, it contains #, which has to be percent-encoded",
				null,
				'Percent-encode it as %23',
			],
			'an IPv6 address without brackets' => [
				"The Policy value (https://2001:db8::1/policy) doesn't follow the URI syntax described in RFC 3986, an IPv6 address has to be in square brackets",
				'https://[2001:db8::1]/policy',
				'Put the IPv6 address in square brackets',
			],
			'a port that is not a number' => [
				"The Policy value (https://example.com:80a/) doesn't follow the URI syntax described in RFC 3986, the port isn't a number",
				null,
				'Use a port number from 0 to 65535, or leave the port out',
			],
			'an IPv6 address and a port that is not a number' => [
				"The Policy value (https://[2001:db8::1]:80a/) doesn't follow the URI syntax described in RFC 3986, the port isn't a number",
				null,
				'Use a port number from 0 to 65535, or leave the port out',
			],
			'a note after a URI with no path' => [
				"The Policy value (https://example.com (preferred)) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			'a note after a URI with a port and no path' => [
				"The Policy value (https://example.com:8080 (alt)) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				null,
				'Remove the spaces, or percent-encode each one as %20',
			],
			'a space after the dns scheme' => [
				"The Policy value (dns: example.com) doesn't follow the URI syntax described in RFC 3986, it contains a space",
				'dns:example.com',
				'Remove the space after the scheme',
			],
			'an openpgp4fpr URI and another URI' => [
				'The Policy value (openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F https://example.com/key.asc) lists more than one URI',
				null,
				'Put each URI in a field of its own',
			],
			'a delete character' => [
				"The Policy value (https://example.com/%7Fpolicy) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				'https://example.com/policy',
				'Remove the control characters',
			],
			'a control character before a slash' => [
				"The Policy value (https://example.com%01/policy) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				'https://example.com/policy',
				'Remove the control characters',
			],
			'two control characters before a slash' => [
				"The Policy value (https://example.com%01%01/policy) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				'https://example.com/policy',
				'Remove the control characters',
			],
			'two control characters after a slash' => [
				"The Policy value (https://example.com/%01%01policy) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				'https://example.com/policy',
				'Remove the control characters',
			],
			'control characters at the end' => [
				"The Policy value (https://example.com/policy%01%01%01) doesn't follow the URI syntax described in RFC 3986, it contains a control character",
				'https://example.com/policy',
				'Remove the control characters',
			],
			'a valid escape in the host and a stray percent sign' => [
				"The Policy value (https://exa%41mple.com/100%) doesn't follow the URI syntax described in RFC 3986, it contains a % not followed by two hexadecimal digits",
				'https://exa%41mple.com/100%25',
				'Percent-encode the % itself, as %25',
			],
			'an unclosed IPv6 address' => [
				"The Policy value (https://[2001:db8::1/policy) doesn't follow the URI syntax described in RFC 3986, the IPv6 address has no closing ]",
				null,
				'Add the ] after the IPv6 address',
			],
			'text after an IPv6 address' => [
				"The Policy value (https://[2001:db8::1]x/) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'two @ before an IPv6 address' => [
				"The Policy value (foo://a@b@[::1]/) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'a character in the host' => [
				"The Policy value (https://exa|mple.com/) doesn't follow the URI syntax described in RFC 3986, it contains | in the host",
				null,
				'Remove it from the host',
			],
			'a character in the port' => [
				"The Policy value (https://example.com:80|80/) doesn't follow the URI syntax described in RFC 3986, the port isn't a number",
				null,
				'Use a port number from 0 to 65535, or leave the port out',
			],
			'an IRI with a character to percent-encode' => [
				"The Policy value (https://h%C3%A1%C4%8Dky.example/a|b) doesn't follow the URI syntax described in RFC 3986, it contains |, which has to be percent-encoded",
				null,
				'Percent-encode it as %7C',
			],
			'a tilde and a character to percent-encode' => [
				"The Policy value (https://example.com/~user/a|b) doesn't follow the URI syntax described in RFC 3986, it contains |, which has to be percent-encoded",
				null,
				'Percent-encode it as %7C',
			],
			'a number sign in a value refused for something else' => [
				"The Policy value (https://example.com:8080:8443/#top) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'an IPv6 address without brackets and a group like a port' => [
				"The Policy value (https://2001:db8::1:8080/policy) doesn't follow the URI syntax described in RFC 3986, an IPv6 address has to be in square brackets",
				null,
				'Put the IPv6 address in square brackets',
			],
			// A port of one digit is unlikely enough
			'an IPv6 address without brackets and a short last group' => [
				"The Policy value (https://fe80::1:4/) doesn't follow the URI syntax described in RFC 3986, an IPv6 address has to be in square brackets",
				'https://[fe80::1:4]/',
				'Put the IPv6 address in square brackets',
			],
			// Nine groups are not an address, the last one is the port
			'an IPv6 address without brackets and a port' => [
				"The Policy value (https://2001:db8:1:2:3:4:5:6:8080/policy) doesn't follow the URI syntax described in RFC 3986, an IPv6 address has to be in square brackets",
				'https://[2001:db8:1:2:3:4:5:6]:8080/policy',
				'Put the IPv6 address in square brackets',
			],
			'an IPv6 address without brackets and a port too large for a group' => [
				"The Policy value (https://2001:db8::1:65000/policy) doesn't follow the URI syntax described in RFC 3986, an IPv6 address has to be in square brackets",
				'https://[2001:db8::1]:65000/policy',
				'Put the IPv6 address in square brackets',
			],
			// No suggestion, it would be refused for the scheme
			'an IPv6 address without brackets in an http URI' => [
				"The Policy value (http://2001:db8::1/policy) doesn't follow the URI syntax described in RFC 3986, an IPv6 address has to be in square brackets",
				null,
				'Put the IPv6 address in square brackets',
			],
			'an IPv6 address without brackets and a hexadecimal last group in an http URI' => [
				"The Policy value (http://2001:db8::ff/policy) doesn't follow the URI syntax described in RFC 3986, an IPv6 address has to be in square brackets",
				null,
				'Put the IPv6 address in square brackets',
			],
			// Not that the port isn't a number, there is none
			'a user name and an IPv6 address without brackets' => [
				"The Policy value (https://user@2001:db8::ff/policy) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'an IPv6 address and a zone without brackets' => [
				"The Policy value (https://fe80::1%25eth0/policy) doesn't follow the URI syntax described in RFC 3986",
				null,
				'Use a URI as the value',
			],
			'an IPv6 address without brackets and a character' => [
				"The Policy value (https://2001:db8::1|/policy) doesn't follow the URI syntax described in RFC 3986, it contains | in the host",
				null,
				'Remove it from the host',
			],
			'two ports' => [
				"The Policy value (https://example.com:8080:8443/) doesn't follow the URI syntax described in RFC 3986",
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
	 * A suggestion is only checked, not explained, so a value of labels before labels is not explained once for each of them.
	 */
	public function testALabelBeforeALabelIsExplainedOnce(): void
	{
		$uri = str_repeat('Note: ', 2000) . 'urn:isbn:0451450523';
		memory_reset_peak_usage();
		$before = memory_get_usage();
		Assert::exception(function () use ($uri): void {
			$this->validator->validate($uri, SecurityTxtPolicyNotUri::class, SecurityTxtPolicyNotHttps::class, SecurityTxtField::Policy);
		}, SecurityTxtError::class);
		// Over 100 MB when each was explained again
		Assert::true(memory_get_peak_usage() - $before < 5_000_000);
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
			SecurityTxtField::Hiring => [SecurityTxtHiringNotUri::class, SecurityTxtHiringNotHttps::class],
			SecurityTxtField::Encryption => [SecurityTxtEncryptionNotUri::class, SecurityTxtEncryptionNotHttps::class],
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
