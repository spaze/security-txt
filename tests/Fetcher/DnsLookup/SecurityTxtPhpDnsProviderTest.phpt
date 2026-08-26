<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtPhpDnsProvider;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\SecurityTxtHost;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
use function Spaze\SecurityTxt\Test\needsInternet;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtPhpDnsProviderTest extends TestCase
{

	public function testGetRecords(): void
	{
		needsInternet();
		$provider = new SecurityTxtPhpDnsProvider();
		$records = $provider->getRecords(new Url('https://example.com/'), SecurityTxtHost::fromString('example.com'));
		Assert::true(filter_var($records->getIpRecord(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false);
		Assert::true($records->getIpv6Record() === null || filter_var($records->getIpv6Record(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false);

		$records = $provider->getRecords(new Url('https://_dmarc.example.com/'), SecurityTxtHost::fromString('_dmarc.example.com'));
		Assert::null($records->getIpRecord());
		Assert::null($records->getIpv6Record());

		Assert::throws(function () use ($provider) {
			$provider->getRecords(new Url('https://nah/'), SecurityTxtHost::fromString('nah'));
		}, SecurityTxtHostNotFoundException::class, "Can't open https://nah/, can't resolve nah");
	}


	public function testGetRecordsInternationalizedHost(): void
	{
		needsInternet();
		// `dns_get_record()` does no IDNA of its own, so asking it for the readable spelling finds nothing at all
		$provider = new SecurityTxtPhpDnsProvider();
		$url = new Url("https://h\u{E1}\u{10D}ky\u{10D}\u{E1}rky.cz/");
		$records = $provider->getRecords($url, new SecurityTxtHost($url));
		Assert::true(filter_var($records->getIpRecord(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false);
	}

}

(new SecurityTxtPhpDnsProviderTest())->run();
