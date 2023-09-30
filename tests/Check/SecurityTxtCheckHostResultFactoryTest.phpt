<?php
/** @noinspection PhpUnhandledExceptionInspection */
/** @noinspection HttpUrlsUsage */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use DateInterval;
use DateTimeImmutable;
use ReflectionProperty;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
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
class SecurityTxtCheckHostResultFactoryTest extends TestCase
{

	public function testCreateFromJson(): void
	{
		$securityTxtFactory = new SecurityTxtFactory();
		$resultFactory = new SecurityTxtCheckHostResultFactory($securityTxtFactory);
		$expectedResult = $this->getResult();
		$actualResult = $resultFactory->createFromJson(json_encode($expectedResult));
		$this->setExpiresInterval($expectedResult);
		$this->setExpiresInterval($actualResult);
		Assert::equal($expectedResult, $actualResult);
	}


	private function setExpiresInterval(SecurityTxtCheckHostResult $result): void
	{
		$expires = $result->getSecurityTxt()->getExpires();
		$reflection = new ReflectionProperty($expires, 'interval');
		$reflection->setValue($expires, new DateInterval('P30D'));
	}


	private function getResult(): SecurityTxtCheckHostResult
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$dateTime = new DateTimeImmutable('2022-08-08T02:40:54+00:00');
		$securityTxt->setExpires(new Expires($dateTime));
		return new SecurityTxtCheckHostResult(
			'www.example.com',
			['http://example.com' => ['https://example.com', 'https://www.example.com']],
			'http://www.example.com/.well-known/security.txt',
			'https://www.example.com/.well-known/security.txt',
			"Hi-ring: https://example.com/hiring\nExpires: " . $dateTime->format(DATE_RFC3339),
			[new SecurityTxtSchemeNotHttps('http://example.com')],
			[new SecurityTxtWellKnownPathOnly()],
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

(new SecurityTxtCheckHostResultFactoryTest())->run();
