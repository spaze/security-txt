<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherFopenClient;
use Tester\Assert;
use Tester\TestCase;
use function Spaze\SecurityTxt\Test\needsInternet;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherFopenClientTest extends TestCase
{

	public function testGetResponse(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherFopenClient();
		$response = $client->getResponse(new SecurityTxtFetcherUrl('https://example.com', []), null);
		Assert::contains('Example Domain', $response->getContents());
		Assert::same(200, $response->getHttpCode());
		Assert::true(str_starts_with($response->getHeader('Content-Type') ?? '', 'text/html'));
		Assert::false($response->isTruncated());
	}


	public function testGetResponseTruncated(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherFopenClient();
		$url = 'http://ipv4.download.thinkbroadband.com/5MB.zip'; // From https://www.thinkbroadband.com/download
		$response = $client->getResponse(new SecurityTxtFetcherUrl($url, []), null);
		Assert::same(200, $response->getHttpCode());
		Assert::true($response->isTruncated());
	}


	public function testGetResponseCannotOpen(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherFopenClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl('https://com.example/', []), null);
		}, SecurityTxtCannotOpenUrlException::class, "Can't open https://com.example/");
	}

}

(new SecurityTxtFetcherFopenClientTest())->run();
