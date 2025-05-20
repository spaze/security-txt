<?php
/** @noinspection HttpUrlsUsage */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Parser\SecurityTxtParseHostResult;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtCheckHostResultFactoryTest extends TestCase
{

	private SecurityTxtParser $parser;
	private SecurityTxtCheckHostResultFactory $checkHostResultFactory;


	public function __construct()
	{
		$validator = new SecurityTxtValidator();
		$signature = new SecurityTxtSignature();
		$expiresFactory = new SecurityTxtExpiresFactory();
		$splitLines = new SecurityTxtSplitLines();
		$this->parser = new SecurityTxtParser($validator, $signature, $expiresFactory, $splitLines);
		$this->checkHostResultFactory = new SecurityTxtCheckHostResultFactory();
	}


	public function testCreate(): void
	{
		$host = 'com.example';
		$email = "mailto:foo@example.com";
		$lines = [
			"Contact: {$email}\n",
			"Expires: 2020-10-15T00:01:02+02:00\n",
		];
		$contents = implode('', $lines);
		$parseStringResult = $this->parser->parseString($contents, 123, true);
		$fetchResult = new SecurityTxtFetchResult(
			'https://com.example/.well-known/security.txt',
			'https://com.example/.well-known/security.txt',
			[],
			$contents,
			$lines,
			[],
			[],
		);
		$parseHostResult = new SecurityTxtParseHostResult(false, $parseStringResult, $fetchResult);
		$checkHostResult = $this->checkHostResultFactory->create($host, $parseHostResult);
		Assert::same($contents, $checkHostResult->getContents());
		Assert::same($host, $checkHostResult->getHost());
		Assert::same($fetchResult, $checkHostResult->getFetchResult());
		Assert::same([], $checkHostResult->getFetchErrors());
		Assert::same([], $checkHostResult->getFetchWarnings());
		Assert::hasKey(2, $checkHostResult->getLineErrors()); // Because Expires is in the past
		Assert::same([], $checkHostResult->getLineWarnings());
		Assert::same([], $checkHostResult->getFileErrors());
		Assert::same([], $checkHostResult->getFileWarnings());
		Assert::same($email, $checkHostResult->getSecurityTxt()->getContact()[0]->getValue());
		Assert::true($checkHostResult->isExpiresSoon());
		Assert::true($checkHostResult->getIsExpired());
		Assert::true($checkHostResult->getExpiryDays() < 0);
		Assert::false($checkHostResult->isValid());
		Assert::true($checkHostResult->isStrictMode());
		Assert::same(123, $checkHostResult->getExpiresWarningThreshold());
	}

}

new SecurityTxtCheckHostResultFactoryTest()->run();
