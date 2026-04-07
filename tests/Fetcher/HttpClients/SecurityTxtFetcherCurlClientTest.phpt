<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use LogicException;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtPhpDnsProvider;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlUserAgentInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherCurlClient;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
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
		$url = new Url('https://example.com/');
		$ipAddress = $this->dnsProvider->getRecords($url, 'example.com')->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for example.com");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl($url, []),
				'example.com',
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
		$url = new Url('http://ipv4.download.thinkbroadband.com/5MB.zip'); // From https://www.thinkbroadband.com/download
		$ipAddress = $this->dnsProvider->getRecords($url, 'ipv4.download.thinkbroadband.com')->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for ipv4.download.thinkbroadband.com");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl($url, []),
				'ipv4.download.thinkbroadband.com',
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
		$ipAddress = $this->dnsProvider->getRecords($url, 'httpbin.org')->getIpRecord();
		if ($ipAddress === null) {
			Assert::fail("Can't find an IP address for httpbin.org");
		} else {
			$response = $client->getResponse(
				new SecurityTxtFetcherUrl($url, []),
				'httpbin.org',
				$ipAddress,
				SecurityTxtIpAddressType::V4,
			);
			Assert::same(200, $response->getHttpCode());
			Assert::false($response->isTruncated());
			Assert::true(strlen($response->getContents()) > 10_000);
		}
	}


	public function testGetResponseSettingHost(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl(new Url('https://httpbin.org/headers'), []), 'foobar', '1.1.1.0', SecurityTxtIpAddressType::V4);
		}, SecurityTxtConnectedToWrongIpAddressException::class, "Can't open https://httpbin.org/headers, connected to %S% instead of 1.1.1.0 as expected");
	}


	public function testGetResponseCannotOpen(): void
	{
		needsInternet();
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client): void {
			$client->getResponse(new SecurityTxtFetcherUrl(new Url('https://com.example/'), []), 'com.example', '1.1.1.0', SecurityTxtIpAddressType::V4);
		}, SecurityTxtCannotOpenUrlException::class, "Can't open https://com.example/");
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
			$client->getResponse(new SecurityTxtFetcherUrl(new Url('https://com.example/'), []), 'com.example', '1.1.1.0', SecurityTxtIpAddressType::V4);
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

}

(new SecurityTxtFetcherCurlClientTest())->run();
