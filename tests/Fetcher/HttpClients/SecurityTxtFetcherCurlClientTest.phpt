<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use LogicException;
use ReflectionMethod;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtPhpDnsProvider;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlUserAgentInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherCurlClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtRedirects;
use Spaze\SecurityTxt\SecurityTxtHost;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
use function Spaze\SecurityTxt\Test\needsInternet;

require __DIR__ . '/../../bootstrap.php';

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
		$url = new Url('https://example.com/');
		$ipAddress = $this->dnsProvider->getRecords($url, new SecurityTxtHost(new Url('https://example.com/')))->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for example.com");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl($url, new SecurityTxtRedirects()),
				new SecurityTxtHost(new Url('https://example.com/')),
				$ipAddress,
				SecurityTxtIpAddressType::V4,
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
		$url = new Url('https://httpbin.org/bytes/31337');
		$ipAddress = $this->dnsProvider->getRecords($url, new SecurityTxtHost(new Url('https://httpbin.org/')))->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for httpbin.org");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl($url, new SecurityTxtRedirects()),
				new SecurityTxtHost(new Url('https://httpbin.org/')),
				$ipAddress,
				SecurityTxtIpAddressType::V4,
			);
			Assert::same(200, $response->getHttpCode());
			Assert::true($response->isTruncated());
		}
	}


	public function testGetResponseMaxResponseLengthSetting(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient(maxResponseLength: 100_000);
		$url = new Url('https://httpbin.org/bytes/31337');
		$ipAddress = $this->dnsProvider->getRecords($url, new SecurityTxtHost(new Url('https://httpbin.org/')))->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for httpbin.org");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl($url, new SecurityTxtRedirects()),
				new SecurityTxtHost(new Url('https://httpbin.org/')),
				$ipAddress,
				SecurityTxtIpAddressType::V4,
			);
			Assert::same(200, $response->getHttpCode());
			Assert::false($response->isTruncated());
			Assert::true(strlen($response->getContents()) > 10_000);
		}
	}


	/**
	 * Data keeps arriving above the stall limit for longer than the timeout, so the timeout is what gives the hop up
	 */
	public function testGetResponseTimeout(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient(timeout: 1, connectTimeout: 1);
		$url = new Url('https://httpbin.org/drip?duration=3&numbytes=150&delay=0');
		$ipAddress = $this->dnsProvider->getRecords($url, new SecurityTxtHost(new Url('https://httpbin.org/')))->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for httpbin.org");
		} else {
			Assert::throws(function () use ($client, $url, $ipAddress): void {
				$client->getResponse(
					new SecurityTxtFetcherUrl($url, new SecurityTxtRedirects()),
					new SecurityTxtHost(new Url('https://httpbin.org/')),
					$ipAddress,
					SecurityTxtIpAddressType::V4,
				);
			}, SecurityTxtCannotOpenUrlException::class, "Can't open https://httpbin.org/drip?duration=3&numbytes=150&delay=0 using its IPv4 address %a% (Timeout was reached)");
		}
	}


	/**
	 * The server answers inside the timeout but only after the stall window derived from it, so the stall detection is what gives the hop up. The delay has to stay between
	 * the two, 5 < 8 < 12 here: move it above the timeout and a hop given up for the wrong reason would still pass this
	 */
	public function testGetResponseStalled(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient(timeout: 12, connectTimeout: 2);
		$url = new Url('https://httpbin.org/delay/8');
		$ipAddress = $this->dnsProvider->getRecords($url, new SecurityTxtHost(new Url('https://httpbin.org/')))->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for httpbin.org");
		} else {
			Assert::throws(function () use ($client, $url, $ipAddress): void {
				$client->getResponse(
					new SecurityTxtFetcherUrl($url, new SecurityTxtRedirects()),
					new SecurityTxtHost(new Url('https://httpbin.org/')),
					$ipAddress,
					SecurityTxtIpAddressType::V4,
				);
			}, SecurityTxtCannotOpenUrlException::class, "Can't open https://httpbin.org/delay/8 using its IPv4 address %a% (Timeout was reached)");
		}
	}


	public function testGetResponseSettingHost(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl(new Url('https://httpbin.org/headers'), new SecurityTxtRedirects()), new SecurityTxtHost(new Url('https://foobar/')), '1.1.1.0', SecurityTxtIpAddressType::V4);
		}, SecurityTxtConnectedToWrongIpAddressException::class, "Can't open https://httpbin.org/headers, connected to %S% instead of 1.1.1.0 as expected");
	}


	public function testGetResponseCannotOpen(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl(new Url('https://com.example/'), new SecurityTxtRedirects()), new SecurityTxtHost(new Url('https://com.example/')), '1.1.1.0', SecurityTxtIpAddressType::V4);
		}, SecurityTxtCannotOpenUrlException::class, "Can't open https://com.example/ using its IPv4 address 1.1.1.0 (%a%)");
	}


	/**
	 * @return list<array{0:string}>
	 */
	public function getInvalidUserAgents(): array
	{
		return [
			["foo\nbar"],
			["foo\r\nbar"],
			["foo\rbar"],
			["foo\tbar"],
		];
	}


	/**
	 * @dataProvider getInvalidUserAgents
	 */
	public function testGetResponseInvalidUserAgent(string $userAgent): void
	{
		$client = new SecurityTxtFetcherCurlClient($userAgent);
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl(new Url('https://com.example/'), new SecurityTxtRedirects()), new SecurityTxtHost(new Url('https://com.example/')), '1.1.1.0', SecurityTxtIpAddressType::V4);
		}, SecurityTxtCannotOpenUrlUserAgentInvalidException::class, "Can't open https://com.example/, the specified user agent contains a control character and is invalid");
	}


	public function testMaxResponseLengthPositive(): void
	{
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(maxResponseLength: 0);
		}, LogicException::class, 'maxResponseLength must be greater than 0');
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(maxResponseLength: -1);
		}, LogicException::class, 'maxResponseLength must be greater than 0');
	}


	public function testTimeoutPositive(): void
	{
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(timeout: 0);
		}, LogicException::class, 'timeout must be greater than 0');
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(timeout: -1);
		}, LogicException::class, 'timeout must be greater than 0');
	}


	public function testConnectTimeoutPositive(): void
	{
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(connectTimeout: 0);
		}, LogicException::class, 'connectTimeout must be greater than 0');
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(connectTimeout: -1);
		}, LogicException::class, 'connectTimeout must be greater than 0');
	}


	public function testConnectTimeoutNotGreaterThanTimeout(): void
	{
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(timeout: 5, connectTimeout: 6);
		}, LogicException::class, 'connectTimeout must not be greater than timeout (timeout is for the whole transfer, connecting included)');
		Assert::throws(function (): void {
			new SecurityTxtFetcherCurlClient(timeout: 3);
		}, LogicException::class, 'connectTimeout must not be greater than timeout (timeout is for the whole transfer, connecting included)');
		Assert::noError(function (): void {
			new SecurityTxtFetcherCurlClient(timeout: 5, connectTimeout: 5);
		});
	}


	/**
	 * Every case in one assertion, keyed by timeout, because the wrong ones together say what broke: timeout 1 catches a window of zero, 11 and up one that keeps growing
	 */
	public function testGetLowSpeedTime(): void
	{
		$expected = [1 => 1, 2 => 1, 3 => 1, 4 => 2, 5 => 2, 9 => 4, 10 => 5, 11 => 5, 30 => 5];
		$actual = [];
		foreach (array_keys($expected) as $timeout) {
			$client = new SecurityTxtFetcherCurlClient(timeout: $timeout, connectTimeout: 1);
			$actual[$timeout] = new ReflectionMethod($client, 'getLowSpeedTime')->invoke($client);
		}
		Assert::same($expected, $actual);
	}

}

(new SecurityTxtFetcherCurlClientTest())->run();
