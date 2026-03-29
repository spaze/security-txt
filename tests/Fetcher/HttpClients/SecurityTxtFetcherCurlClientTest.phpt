<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtPhpDnsProvider;
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

	private SecurityTxtPhpDnsProvider $dnsProvider;


	public function __construct()
	{
		$this->dnsProvider = new SecurityTxtPhpDnsProvider();
	}


	public function testGetResponse(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		$ipAddress = $this->dnsProvider->getRecords('...', 'example.com')->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for example.com");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl('https://example.com', []),
				'example.com',
				$ipAddress,
				DNS_A,
			);
			Assert::contains('Example Domain', $response->getContents());
			Assert::same(200, $response->getHttpCode());
			Assert::true(str_starts_with($response->getHeader('Content-Type') ?? '', 'text/html'));
			Assert::false($response->isTruncated());
		}
	}


	public function testGetResponseTruncated(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		$url = 'http://ipv4.download.thinkbroadband.com/5MB.zip'; // From https://www.thinkbroadband.com/download
		$ipAddress = $this->dnsProvider->getRecords('...', 'ipv4.download.thinkbroadband.com')->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for ipv4.download.thinkbroadband.com");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl($url, []),
				'ipv4.download.thinkbroadband.com',
				$ipAddress,
				DNS_A,
			);
			Assert::same(200, $response->getHttpCode());
			Assert::true($response->isTruncated());
		}
	}


	public function testGetResponseSettingHost(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl('https://httpbin.org/headers', []), 'foobar', '1.1.1.0', DNS_A);
		}, SecurityTxtConnectedToWrongIpAddressException::class, "Can't open https://httpbin.org/headers, connected to %S% instead of 1.1.1.0 as expected");
	}


	public function testGetResponseCannotOpen(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl('https://com.example/', []), 'com.example', '1.1.1.0', DNS_A);
		}, SecurityTxtCannotOpenUrlException::class, "Can't open https://com.example/");
	}

}

(new SecurityTxtFetcherCurlClientTest())->run();
