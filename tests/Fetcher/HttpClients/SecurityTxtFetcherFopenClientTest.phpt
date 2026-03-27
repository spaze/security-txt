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
		$response = $client->getResponse(new SecurityTxtFetcherUrl('https://example.com', [], '1.1.1.0', DNS_A), null);
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
		$response = $client->getResponse(new SecurityTxtFetcherUrl($url, [], '1.1.1.0', DNS_A), null);
		Assert::same(200, $response->getHttpCode());
		Assert::true($response->isTruncated());
	}


	public function testGetResponseContextHost(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherFopenClient();
		$response = $client->getResponse(new SecurityTxtFetcherUrl('https://httpbin.org/headers', [], '1.1.1.0', DNS_A), 'www.httpbin.org');
		Assert::same(200, $response->getHttpCode());
		$json = $response->getContents();
		$headers = json_decode($json, true);
		if (
			is_array($headers)
			&& is_array($headers['headers'] ?? null)
			&& is_string($headers['headers']['Host'] ?? null)
		) {
			Assert::same('www.httpbin.org', $headers['headers']['Host']);
		} else {
			Assert::fail("Cannot access headers > host in the JSON response ({$json})");
		}
	}


	public function testGetResponseCannotOpen(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherFopenClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl('https://com.example/', [], '1.1.1.0', DNS_A), null);
		}, SecurityTxtCannotOpenUrlException::class, "Can't open https://com.example/");
	}

}

(new SecurityTxtFetcherFopenClientTest())->run();
