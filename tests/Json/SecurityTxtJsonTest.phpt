<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use DateTimeImmutable;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHostResult;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSchemeNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtJsonTest extends TestCase
{

	private SecurityTxtJson $securityTxtJson;
	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;


	public function __construct()
	{
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
		$this->securityTxtJson = new SecurityTxtJson(new SecurityTxtSplitLines());
	}


	public function testCreateCheckHostResultFromJsonValues(): void
	{
		$expectedResult = $this->getCheckHostResult();
		$encoded = json_encode($expectedResult);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$actualResult = $this->securityTxtJson->createCheckHostResultFromJsonValues($decoded);
		Assert::equal($expectedResult, $actualResult);
	}


	private function getCheckHostResult(): SecurityTxtCheckHostResult
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$dateTime = new DateTimeImmutable('2022-08-08T02:40:54+00:00');
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create($dateTime));
		$securityTxt = $securityTxt->withSignatureVerifyResult(new SecurityTxtSignatureVerifyResult('LeKeyFingerPrint', new DateTimeImmutable('-2 weeks noon +02:00')));
		$lines = ["Hi-ring: https://example.com/hiring\n", 'Expires: ' . $dateTime->format(SecurityTxtExpires::FORMAT)];
		$fetchResult = new SecurityTxtFetchResult(
			'http://www.example.com/.well-known/security.txt',
			'https://www.example.com/.well-known/security.txt',
			['http://example.com' => ['https://example.com', 'https://www.example.com']],
			implode('', $lines),
			true,
			$lines,
			[new SecurityTxtSchemeNotHttps('http://example.com')],
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
			true,
			10,
			false,
			true,
			15,
		);
	}


	public function testCreateFetchResultFromJsonValues(): void
	{
		$lines = ["Contact: mailto:example@example.com\r\n", "Expires: 2030-12-31T23:59:59.000Z\r\n", "Preferred-Languages: en; cs"];
		$result = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[
				'https://example.com/.well-known/security.txt' => ['https://www.example.com/.well-known/security.txt'],
				'https://example.com/security.txt' => ['https://www.example.com/security.txt'],
			],
			implode($lines),
			true,
			$lines,
			[new SecurityTxtContentTypeWrongCharset('https://example.com/security.txt', 'text/plain', null)],
			[new SecurityTxtTopLevelPathOnly()],
		);
		$encoded = json_encode($result);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		Assert::equal($result, $this->securityTxtJson->createFetchResultFromJsonValues($decoded));
	}


	public function testCreateFetcherExceptionFromJsonValues(): void
	{
		$exception = new SecurityTxtTooManyRedirectsException('https://example.com', ['https://example.com', 'https://www.example.com'], 1);
		$encoded = json_encode(['error' => $exception]);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$exceptionFromJson = $this->securityTxtJson->createFetcherExceptionFromJsonValues($decoded);
		Assert::type($exception::class, $exceptionFromJson);
		Assert::same($exception->getMessage(), $exceptionFromJson->getMessage());
	}

}

new SecurityTxtJsonTest()->run();
