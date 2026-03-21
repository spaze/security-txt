<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtPhpDnsProvider;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Tester\Assert;
use Tester\TestCase;
use function Spaze\SecurityTxt\Test\needsInternet;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtPhpDnsProviderTest extends TestCase
{

	public function testGetRecords(): void
	{
		needsInternet();
		$provider = new SecurityTxtPhpDnsProvider();
		$records = $provider->getRecords('https://example.com/', 'example.com');
		Assert::true(filter_var($records->getIpRecord(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false);
		Assert::true($records->getIpv6Record() === null || filter_var($records->getIpv6Record(), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false);

		$records = $provider->getRecords('https://_dmarc.example.com/', '_dmarc.example.com');
		Assert::null($records->getIpRecord());
		Assert::null($records->getIpv6Record());

		Assert::throws(function () use ($provider) {
			$provider->getRecords('https://nah/', 'nah');
		}, SecurityTxtHostNotFoundException::class, "Can't open https://nah/, can't resolve nah");
	}

}

(new SecurityTxtPhpDnsProviderTest())->run();
