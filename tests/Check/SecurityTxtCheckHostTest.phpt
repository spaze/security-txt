<?php
/** @noinspection HttpUrlsUsage */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtCheckHostTest extends TestCase
{

	private DateTimeImmutable $expires;
	private SecurityTxtExpiresFactory $expiresFactory;


	public function __construct()
	{
		$this->expires = new DateTimeImmutable('+25 days');
		$this->expiresFactory = new SecurityTxtExpiresFactory();
	}


	public function testJsonSerialize(): void
	{
		$result = $this->getResult();
		$expected = [
			'class' => 'Spaze\SecurityTxt\Check\SecurityTxtCheckHostResult',
			'host' => 'www.example.com',
			'fetchResult' => [
				'class' => 'Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult',
				'constructedUrl' => 'http://www.example.com/.well-known/security.txt',
				'finalUrl' => 'https://www.example.com/.well-known/security.txt',
				'redirects' => [
					'http://example.com' => ['https://example.com', 'https://www.example.com'],
				],
				'contents' => "Hi-ring: https://example.com/hiring\nExpires: " . $this->expires->format(SecurityTxtExpires::FORMAT),
				'isTruncated' => true,
				'errors' => [
					[
						'class' => 'Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps',
						'params' => ['http://example.com'],
						'message' => 'The file at http://example.com must use HTTPS',
						'messageFormat' => 'The file at %s must use HTTPS',
						'messageValues' => ['http://example.com'],
						'since' => 'draft-foudil-securitytxt-06',
						'correctValue' => 'https://example.com',
						'howToFix' => 'Use HTTPS to serve the security.txt file',
						'howToFixFormat' => 'Use HTTPS to serve the %s file',
						'howToFixValues' => ['security.txt'],
						'specSection' => '3',
						'seeAlsoSections' => [],
					],
				],
				'warnings' => [
					[
						'class' => 'Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly',
						'params' => [],
						'message' => 'security.txt not found at the top-level path',
						'messageFormat' => '%s not found at the top-level path',
						'messageValues' => ['security.txt'],
						'since' => 'draft-foudil-securitytxt-02',
						'correctValue' => null,
						'howToFix' => 'Redirect the top-level file to the one under the /.well-known/ path',
						'howToFixFormat' => 'Redirect the top-level file to the one under the %s path',
						'howToFixValues' => ['/.well-known/'],
						'specSection' => '3',
						'seeAlsoSections' => [],
					],
				],
			],
			'fetchErrors' => [
				[
					'class' => SecurityTxtFileLocationNotHttps::class,
					'params' => ['http://example.com'],
					'message' => 'The file at http://example.com must use HTTPS',
					'messageFormat' => 'The file at %s must use HTTPS',
					'messageValues' => ['http://example.com'],
					'since' => 'draft-foudil-securitytxt-06',
					'correctValue' => 'https://example.com',
					'howToFix' => 'Use HTTPS to serve the security.txt file',
					'howToFixFormat' => 'Use HTTPS to serve the %s file',
					'howToFixValues' => ['security.txt'],
					'specSection' => '3',
					'seeAlsoSections' => [],
				],
			],
			'fetchWarnings' => [
				[
					'class' => SecurityTxtWellKnownPathOnly::class,
					'params' => [],
					'message' => 'security.txt not found at the top-level path',
					'messageFormat' => '%s not found at the top-level path',
					'messageValues' => ['security.txt'],
					'since' => 'draft-foudil-securitytxt-02',
					'correctValue' => null,
					'howToFix' => 'Redirect the top-level file to the one under the /.well-known/ path',
					'howToFixFormat' => 'Redirect the top-level file to the one under the %s path',
					'howToFixValues' => ['/.well-known/'],
					'specSection' => '3',
					'seeAlsoSections' => [],
				],
			],
			'lineErrors' => [
				2 => [
					[
						'class' => SecurityTxtLineNoEol::class,
						'params' => ['Contact: https://example.com/contact'],
						'message' => "The line (Contact: https://example.com/contact) doesn't end with neither <CRLF> nor <LF>",
						'messageFormat' => "The line (%s) doesn't end with neither %s nor %s",
						'messageValues' => ['Contact: https://example.com/contact', '<CRLF>', '<LF>'],
						'since' => 'draft-foudil-securitytxt-03',
						'correctValue' => 'Contact: https://example.com/contact<LF>',
						'howToFix' => 'End the line with either <CRLF> or <LF>',
						'howToFixFormat' => 'End the line with either %s or %s',
						'howToFixValues' => ['<CRLF>', '<LF>'],
						'specSection' => '2.2',
						'seeAlsoSections' => ['4'],
					],
				],
			],
			'lineWarnings' => [
				1 => [
					[
						'class' => SecurityTxtPossibelFieldTypo::class,
						'params' => ['Hi-ring', SecurityTxtField::Hiring->value, 'Hi-ring: https://example.com/hiring'],
						'message' => 'Field Hi-ring may be a typo, did you mean Hiring?',
						'messageFormat' => 'Field %s may be a typo, did you mean %s?',
						'messageValues' => ['Hi-ring', SecurityTxtField::Hiring->value],
						'since' => null,
						'correctValue' => 'Hiring: https://example.com/hiring',
						'howToFix' => 'Change Hi-ring to Hiring',
						'howToFixFormat' => 'Change %s to %s',
						'howToFixValues' => ['Hi-ring', SecurityTxtField::Hiring->value],
						'specSection' => null,
						'seeAlsoSections' => [],
					],
				],
			],
			'fileErrors' => [
				[
					'class' => SecurityTxtNoContact::class,
					'params' => [],
					'message' => 'The Contact field must always be present',
					'messageFormat' => 'The %s field must always be present',
					'messageValues' => [SecurityTxtField::Contact->value],
					'since' => 'draft-foudil-securitytxt-00',
					'correctValue' => null,
					'howToFix' => 'Add at least one Contact field with a value that follows the URI syntax described in RFC 3986. This means that "mailto" and "tel" URI schemes must be used when specifying email addresses and telephone numbers, e.g. mailto:security@example.com',
					'howToFixFormat' => 'Add at least one %s field with a value that follows the URI syntax described in RFC 3986. This means that "mailto" and "tel" URI schemes must be used when specifying email addresses and telephone numbers, e.g. %s',
					'howToFixValues' => [SecurityTxtField::Contact->value, 'mailto:security@example.com'],
					'specSection' => '2.5.3',
					'seeAlsoSections' => ['2.5.4'],
				],
			],
			'fileWarnings' => [
				[
					'class' => SecurityTxtSignatureExtensionNotLoaded::class,
					'params' => [],
					'message' => 'The gnupg extension is not available, cannot verify or create signatures',
					'messageFormat' => 'The %s extension is not available, cannot verify or create signatures',
					'messageValues' => ['gnupg'],
					'since' => 'draft-foudil-securitytxt-01',
					'correctValue' => null,
					'howToFix' => 'Load the gnupg extension',
					'howToFixFormat' => 'Load the %s extension',
					'howToFixValues' => ['gnupg'],
					'specSection' => '2.3',
					'seeAlsoSections' => [],
				],
			],
			'securityTxt' => [
				'fileLocation' => 'https://foo.example/.well-known/security.txt',
				'expires' => [
					'dateTime' => $this->expires->format(SecurityTxtExpires::FORMAT),
					'isExpired' => false,
					'inDays' => 24,
				],
				'signatureVerifyResult' => null,
				'preferredLanguages' => null,
				'canonical' => [],
				'contact' => [],
				'acknowledgments' => [],
				'hiring' => [],
				'policy' => [],
				'encryption' => [],
			],
			'expired' => false,
			'expiryDays' => 150,
			'valid' => false,
			'strictMode' => true,
			'expiresWarningThreshold' => 15,
		];
		$json = json_encode($result);
		assert(is_string($json));
		Assert::same($expected, json_decode($json, true));
	}


	private function getResult(): SecurityTxtCheckHostResult
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setFileLocation('https://foo.example/.well-known/security.txt');
		$securityTxt->setExpires($this->expiresFactory->create($this->expires));
		$lines = ["Hi-ring: https://example.com/hiring\n", 'Expires: ' . $this->expires->format(SecurityTxtExpires::FORMAT)];
		$fetchResult = new SecurityTxtFetchResult(
			'http://www.example.com/.well-known/security.txt',
			'https://www.example.com/.well-known/security.txt',
			['http://example.com' => ['https://example.com', 'https://www.example.com']],
			implode($lines),
			true,
			$lines,
			[new SecurityTxtFileLocationNotHttps('http://example.com')],
			[new SecurityTxtWellKnownPathOnly()],
		);
		return new SecurityTxtCheckHostResult(
			'www.example.com',
			$fetchResult,
			$fetchResult->getErrors(),
			$fetchResult->getWarnings(),
			[2 => [new SecurityTxtLineNoEol('Contact: https://example.com/contact')]],
			[1 => [new SecurityTxtPossibelFieldTypo('Hi-ring', SecurityTxtField::Hiring->value, 'Hi-ring: https://example.com/hiring')]],
			[new SecurityTxtNoContact()],
			[new SecurityTxtSignatureExtensionNotLoaded()],
			$securityTxt,
			false,
			150,
			false,
			true,
			15,
		);
	}

}

(new SecurityTxtCheckHostTest())->run();
