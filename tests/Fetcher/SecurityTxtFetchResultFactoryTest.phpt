<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Json\SecurityTxtJson;
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
		$resultFactory = new SecurityTxtFetchResultFactory(new SecurityTxtJson());
		$result = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[
				'https://example.com/.well-known/security.txt' => ['https://www.example.com/.well-known/security.txt'],
				'https://example.com/security.txt' => ['https://www.example.com/security.txt'],
			],
			"Contact: mailto:example@example.com\r\nExpires: 2030-12-31T23:59:59.000Z\r\nPreferred-Languages: en; cs",
			[new SecurityTxtContentTypeWrongCharset('https://example.com/security.txt', 'text/plain', null)],
			[new SecurityTxtTopLevelPathOnly()],
		);
		$json = json_encode($result);
		Assert::equal($result, $resultFactory->createFromJsonValues(json_decode($json, true)));
	}

}

new SecurityTxtFetchResultFactoryTest()->run();
