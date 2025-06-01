<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherFetchHostResultTest extends TestCase
{

	public function testGetContentTypeHeader(): void
	{
		$response = new SecurityTxtFetcherResponse(200, ['content-type' => 'tExt/HtMl; charset=Win-1337'], 'contents', true);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', DNS_A, 200, $response);
		$contentType = $wellKnown->getContentType();
		assert($contentType !== null);
		Assert::same('text/html', $contentType->getLowercaseContentType());
		Assert::same('charset=win-1337', $contentType->getLowercaseCharset());
	}

}

new SecurityTxtFetcherFetchHostResultTest()->run();
