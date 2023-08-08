<?php
/** @noinspection HttpUrlsUsage */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSchemeNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class SecurityTxtCheckHostTest extends TestCase
{

	private DateTimeImmutable $expires;


	public function __construct()
	{
		$this->expires = new DateTimeImmutable('+1 month');
	}


	public function testJsonSerialize(): void
	{
		$result = $this->getResult();
		$expected = [
			'host' => 'www.example.com',
			'redirects' => [
				'http://example.com' => ['https://example.com', 'https://www.example.com'],
			],
			'constructedUrl' => 'http://www.example.com/.well-known/security.txt',
			'finalUrl' => 'https://www.example.com/.well-known/security.txt',
			'contents' => "Hi-ring: https://example.com/hiring\nExpires: " . $this->expires->format(DATE_RFC3339),
			'fetchErrors' => [
				[
					'message' => 'The file at `http://example.com` must use HTTPS',
					'messageFormat' => 'The file at `%s` must use HTTPS',
					'messageValues' => ['http://example.com'],
					'since' => 'draft-foudil-securitytxt-06',
					'correctValue' => 'https://example.com',
					'howToFix' => 'Use HTTPS to serve the `security.txt` file',
					'howToFixFormat' => 'Use HTTPS to serve the `security.txt` file',
					'howToFixValues' => [],
					'specSection' => '3',
					'seeAlsoSections' => [],
				],
			],
			'fetchWarnings' => [
				[
					'message' => '`security.txt` not found at the top-level path',
					'messageFormat' => '`security.txt` not found at the top-level path',
					'messageValues' => [],
					'since' => 'draft-foudil-securitytxt-02',
					'correctValue' => null,
					'howToFix' => 'Redirect the top-level file to the one under the `/.well-known/` path',
					'howToFixFormat' => 'Redirect the top-level file to the one under the `/.well-known/` path',
					'howToFixValues' => [],
					'specSection' => '3',
					'seeAlsoSections' => [],
				],
			],
			'parseErrors' => [
				2 => [
					[
						'message' => "The line (`Contact: https://example.com/contact`) doesn't end with neither <CRLF> nor <LF>",
						'messageFormat' => "The line (`%s`) doesn't end with neither <CRLF> nor <LF>",
						'messageValues' => ['Contact: https://example.com/contact'],
						'since' => 'draft-foudil-securitytxt-03',
						'correctValue' => 'Contact: https://example.com/contact<LF>',
						'howToFix' => 'End the line with either <CRLF> or <LF>',
						'howToFixFormat' => 'End the line with either <CRLF> or <LF>',
						'howToFixValues' => [],
						'specSection' => '2.2',
						'seeAlsoSections' => ['4'],
					],
				],
			],
			'parseWarnings' => [
				1 => [
					[
						'message' => 'Field `Hi-ring` may be a typo, did you mean `Hiring`?',
						'messageFormat' => 'Field `%s` may be a typo, did you mean `%s`?',
						'messageValues' => ['Hi-ring', 'Hiring'],
						'since' => null,
						'correctValue' => 'Hiring: https://example.com/hiring',
						'howToFix' => 'Change `Hi-ring` to `Hiring`',
						'howToFixFormat' => 'Change `%s` to `%s`',
						'howToFixValues' => ['Hi-ring', 'Hiring'],
						'specSection' => null,
						'seeAlsoSections' => [],
					],
				],
			],
			'fileErrors' => [
				[
					'message' => 'The `Contact` field must always be present',
					'messageFormat' => 'The `Contact` field must always be present',
					'messageValues' => [],
					'since' => 'draft-foudil-securitytxt-00',
					'correctValue' => null,
					'howToFix' => 'Add at least one `Contact` field with a value that follows the URI syntax described in RFC 3986. This means that "mailto" and "tel" URI schemes must be used when specifying email addresses and telephone numbers, e.g. mailto:security@example.com',
					'howToFixFormat' => 'Add at least one `Contact` field with a value that follows the URI syntax described in RFC 3986. This means that "mailto" and "tel" URI schemes must be used when specifying email addresses and telephone numbers, e.g. mailto:security@example.com',
					'howToFixValues' => [],
					'specSection' => '2.5.3',
					'seeAlsoSections' => ['2.5.4'],
				],
			],
			'fileWarnings' => [
				[
					'message' => 'The `gnupg` extension is not available, cannot verify or create signatures',
					'messageFormat' => 'The `gnupg` extension is not available, cannot verify or create signatures',
					'messageValues' => [],
					'since' => 'draft-foudil-securitytxt-01',
					'correctValue' => null,
					'howToFix' => 'Load the `gnupg` extension',
					'howToFixFormat' => 'Load the `gnupg` extension',
					'howToFixValues' => [],
					'specSection' => '2.3',
					'seeAlsoSections' => [],
				],
			],
			'securityTxt' => [
				'expires' => ['dateTime' => $this->expires->format(DATE_RFC3339)],
				'signatureVerifyResult' => null,
				'preferredLanguages' => null,
				'canonical' => [],
				'contact' => [],
				'acknowledgments' => [],
				'hiring' => [],
				'policy' => [],
				'encryption' => [],
			],
			'expiresSoon' => false,
			'expired' => false,
			'expiryDays' => 150,
			'valid' => false,
			'strictMode' => true,
			'expiresWarningThreshold' => 15,
		];
		Assert::same($expected, json_decode(json_encode($result), true));
	}


	public function testJsonEncodeSimplified(): void
	{
		$result = $this->getResult();
		$expected = $this->getSimplifiedJson();
		Assert::same($expected, json_decode($result->jsonEncodeSimplified(), true));
	}


	public function testCreateFromSimplifiedJson(): void
	{
		Assert::equal(json_encode($this->getSimplifiedJson()), $this->getResult()->jsonEncodeSimplified());
	}


	private function getResult(): SecurityTxtCheckHostResult
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setExpires(new Expires($this->expires));
		return new SecurityTxtCheckHostResult(
			'www.example.com',
			['http://example.com' => ['https://example.com', 'https://www.example.com']],
			'http://www.example.com/.well-known/security.txt',
			'https://www.example.com/.well-known/security.txt',
			"Hi-ring: https://example.com/hiring\nExpires: " . $this->expires->format(DATE_RFC3339),
			[new SecurityTxtSchemeNotHttps('http://example.com')],
			[new SecurityTxtWellKnownPathOnly()],
			[2 => [new SecurityTxtLineNoEol('Contact: https://example.com/contact')]],
			[1 => [new SecurityTxtPossibelFieldTypo('Hi-ring', SecurityTxtField::Hiring->value, 'Hi-ring: https://example.com/hiring')]],
			[new SecurityTxtNoContact()],
			[new SecurityTxtSignatureExtensionNotLoaded()],
			$securityTxt,
			false,
			false,
			150,
			false,
			true,
			15,
		);
	}


	private function getSimplifiedJson(): array
	{
		return [
			'host' => 'www.example.com',
			'redirects' => [
				'http://example.com' => ['https://example.com', 'https://www.example.com'],
			],
			'constructedUrl' => 'http://www.example.com/.well-known/security.txt',
			'finalUrl' => 'https://www.example.com/.well-known/security.txt',
			'contents' => "Hi-ring: https://example.com/hiring\nExpires: " . $this->expires->format(DATE_RFC3339),
			'fetchErrors' => [
				[
					'class' => SecurityTxtSchemeNotHttps::class,
					'params' => ['http://example.com'],
				],
			],
			'fetchWarnings' => [
				[
					'class' => SecurityTxtWellKnownPathOnly::class,
					'params' => [],
				],
			],
			'parseErrors' => [
				2 => [
					[
						'class' => SecurityTxtLineNoEol::class,
						'params' => ['Contact: https://example.com/contact'],
					],
				],
			],
			'parseWarnings' => [
				1 => [
					[
						'class' => SecurityTxtPossibelFieldTypo::class,
						'params' => ['Hi-ring', SecurityTxtField::Hiring->value, 'Hi-ring: https://example.com/hiring'],
					],
				],
			],
			'fileErrors' => [
				[
					'class' => SecurityTxtNoContact::class,
					'params' => [],
				],
			],
			'fileWarnings' => [
				[
					'class' => SecurityTxtSignatureExtensionNotLoaded::class,
					'params' => [],
				],
			],
			'securityTxt' => [
				'expires' => ['dateTime' => $this->expires->format(DATE_RFC3339)],
				'signatureVerifyResult' => null,
				'preferredLanguages' => null,
				'canonical' => [],
				'contact' => [],
				'acknowledgments' => [],
				'hiring' => [],
				'policy' => [],
				'encryption' => [],
			],
			'expiresSoon' => false,
			'expired' => false,
			'expiryDays' => 150,
			'valid' => false,
			'strictMode' => true,
			'expiresWarningThreshold' => 15,
		];
	}

}

(new SecurityTxtCheckHostTest())->run();
