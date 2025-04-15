<?php
/** @noinspection PhpUnhandledExceptionInspection */
/** @noinspection HttpUrlsUsage */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use DateInterval;
use DateTimeImmutable;
use ReflectionProperty;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResultFactory;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Json\SecurityTxtJson;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtFactory;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
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
final class SecurityTxtCheckHostResultFactoryTest extends TestCase
{

	public function testCreateFromJson(): void
	{
		$securityTxtFactory = new SecurityTxtFactory();
		$json = new SecurityTxtJson();
		$fetchResultFactory = new SecurityTxtFetchResultFactory($json);
		$resultFactory = new SecurityTxtCheckHostResultFactory($securityTxtFactory, $json, $fetchResultFactory);
		$expectedResult = $this->getResult();
		$encoded = json_encode($expectedResult);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$actualResult = $resultFactory->createFromJsonValues($decoded);
		$this->setExpiresInterval($expectedResult);
		$this->setExpiresInterval($actualResult);
		Assert::equal($expectedResult, $actualResult);
	}


	private function setExpiresInterval(SecurityTxtCheckHostResult $result): void
	{
		$expires = $result->getSecurityTxt()->getExpires();
		assert($expires instanceof Expires);
		$reflection = new ReflectionProperty($expires, 'interval');
		$reflection->setValue($expires, new DateInterval('P30D'));
	}


	private function getResult(): SecurityTxtCheckHostResult
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$dateTime = new DateTimeImmutable('2022-08-08T02:40:54+00:00');
		$securityTxt->setExpires(new Expires($dateTime));
		$fetchResult = new SecurityTxtFetchResult(
			'http://www.example.com/.well-known/security.txt',
			'https://www.example.com/.well-known/security.txt',
			['http://example.com' => ['https://example.com', 'https://www.example.com']],
			"Hi-ring: https://example.com/hiring\nExpires: " . $dateTime->format(DATE_RFC3339),
			[new SecurityTxtSchemeNotHttps('http://example.com')],
			[new SecurityTxtWellKnownPathOnly()],
		);

		return new SecurityTxtCheckHostResult(
			'www.example.com',
			$fetchResult->getRedirects(),
			$fetchResult->getConstructedUrl(),
			$fetchResult->getFinalUrl(),
			$fetchResult->getContents(),
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

}

new SecurityTxtCheckHostResultFactoryTest()->run();
