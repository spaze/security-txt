<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherCurlClient;
use Tester\Assert;
use Tester\TestCase;
use function Spaze\SecurityTxt\Test\needsInternet;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherCurlClientTest extends TestCase
{

	public function testGetResponse(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		$response = $client->getResponse(new SecurityTxtFetcherUrl('https://example.com', [], '104.18.26.120', DNS_A), 'example.com');
		Assert::contains('Example Domain', $response->getContents());
		Assert::same(200, $response->getHttpCode());
		Assert::true(str_starts_with($response->getHeader('Content-Type') ?? '', 'text/html'));
		Assert::false($response->isTruncated());
	}


	public function testGetResponseTruncated(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		$url = 'http://ipv4.download.thinkbroadband.com/5MB.zip'; // From https://www.thinkbroadband.com/download
		$response = $client->getResponse(new SecurityTxtFetcherUrl($url, [], '80.249.99.148', DNS_A), 'ipv4.download.thinkbroadband.com');
		Assert::same(200, $response->getHttpCode());
		Assert::true($response->isTruncated());
	}


	public function testGetResponseSettingHost(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl('https://httpbin.org/headers', [], '1.1.1.0', DNS_A), 'foobar');
		}, SecurityTxtConnectedToWrongIpAddressException::class, "Can't open https://httpbin.org/headers, connected to %S% instead of 1.1.1.0 as expected");
	}


	public function testGetResponseCannotOpen(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl('https://com.example/', [], '1.1.1.0', DNS_A), 'com.example');
		}, SecurityTxtCannotOpenUrlException::class, "Can't open https://com.example/");
	}

}

(new SecurityTxtFetcherCurlClientTest())->run();
