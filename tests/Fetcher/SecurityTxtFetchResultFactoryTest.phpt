<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Json\SecurityTxtJson;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetchResultFactoryTest extends TestCase
{

	public function testCreateFromJson(): void
	{
		$validator = new SecurityTxtValidator();
		$signature = new SecurityTxtSignature();
		$expiresFactory = new SecurityTxtExpiresFactory();
		$parser = new SecurityTxtParser($validator, $signature, $expiresFactory);
		$resultFactory = new SecurityTxtFetchResultFactory(new SecurityTxtJson(), $parser);
		$lines = ["Contact: mailto:example@example.com\r\n", "Expires: 2030-12-31T23:59:59.000Z\r\n", "Preferred-Languages: en; cs"];
		$result = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[
				'https://example.com/.well-known/security.txt' => ['https://www.example.com/.well-known/security.txt'],
				'https://example.com/security.txt' => ['https://www.example.com/security.txt'],
			],
			implode($lines),
			$lines,
			[new SecurityTxtContentTypeWrongCharset('https://example.com/security.txt', 'text/plain', null)],
			[new SecurityTxtTopLevelPathOnly()],
		);
		$json = json_encode($result);
		assert(is_string($json));
		$decoded = json_decode($json, true);
		assert(is_array($decoded));
		Assert::equal($result, $resultFactory->createFromJsonValues($decoded));
	}

}

new SecurityTxtFetchResultFactoryTest()->run();
