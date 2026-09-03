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
use Spaze\SecurityTxt\SecurityTxtHost;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtCheckHostResultTest extends TestCase
{

	private DateTimeImmutable $expires;
	private SecurityTxtExpiresFactory $expiresFactory;


	public function __construct()
	{
		$this->expires = new DateTimeImmutable('+25 days');
		$this->expiresFactory = new SecurityTxtExpiresFactory();
	}


	public function testGetters(): void
	{
		$result = $this->getResult();
		Assert::same(['http://example.com' => ['https://example.com', 'https://www.example.com']], $result->getRedirects());
		Assert::same('http://www.example.com/.well-known/security.txt', $result->getConstructedUrl()->toUnicodeString());
		Assert::same('https://www.example.com/.well-known/security.txt', $result->getFinalUrl()->toUnicodeString());
	}


	public function testJsonSerialize(): void
	{
		$expected = [
			'class' => 'Spaze\SecurityTxt\Check\SecurityTxtCheckHostResult',
			'formatVersion' => 1,
			'host' => 'www.example.com',
			'fetchResult' => [
				'class' => 'Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult',
				'formatVersion' => 1,
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
					],
				],
				'warnings' => [
					[
						'class' => 'Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly',
						'params' => [],
					],
				],
			],
			'fetchErrors' => [
				[
					'class' => SecurityTxtFileLocationNotHttps::class,
					'params' => ['http://example.com'],
				],
			],
			'fetchWarnings' => [
				[
					'class' => SecurityTxtWellKnownPathOnly::class,
					'params' => [],
				],
			],
			'lineErrors' => [
				2 => [
					[
						'class' => SecurityTxtLineNoEol::class,
						'params' => ['Contact: https://example.com/contact'],
					],
				],
			],
			'lineWarnings' => [
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
				'fileLocation' => 'https://foo.example/.well-known/security.txt',
				'fields' => [
					[
						'Expires' => [
							'dateTime' => $this->expires->format(SecurityTxtExpires::FORMAT),
							'isExpired' => false,
							'inDays' => 24,
						],
					],
				],
				'signatureVerifyResult' => null,
			],
			'expired' => false,
			'expiryDays' => 150,
			'valid' => false,
			'strictMode' => true,
			'expiresWarningThreshold' => 15,
		];
		$json = json_encode($this->getResult());
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
			new Url('http://www.example.com/.well-known/security.txt'),
			new Url('https://www.example.com/.well-known/security.txt'),
			['http://example.com' => ['https://example.com', 'https://www.example.com']],
			implode($lines),
			true,
			$lines,
			[new SecurityTxtFileLocationNotHttps('http://example.com')],
			[new SecurityTxtWellKnownPathOnly()],
		);
		return new SecurityTxtCheckHostResult(
			new SecurityTxtHost(new Url('https://www.example.com')),
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

(new SecurityTxtCheckHostResultTest())->run();
