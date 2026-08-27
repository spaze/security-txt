<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotPublicException;
use Spaze\SecurityTxt\SecurityTxtHost;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtIpAddressValidatorTest extends TestCase
{

	private SecurityTxtIpAddressValidator $validator;


	public function __construct()
	{
		$this->validator = new SecurityTxtIpAddressValidator();
	}


	/**
	 * `fromString()` rather than a bare `new`, so a fixture spelled a way production would refuse is refused here too: `808` parses to the host `0.0.3.40` and `Example.COM`
	 * to `example.com`, and a data row written against the spelling typed here would otherwise assert a message that can never be produced.
	 *
	 * @throws SecurityTxtCannotParseHostnameException
	 */
	private function host(string $host): SecurityTxtHost
	{
		return SecurityTxtHost::fromString($host);
	}


	/**
	 * @return list<array{0:string, 1:SecurityTxtIpAddressType, 2:bool}>
	 */
	public function getIpAddresses(): array
	{
		return [
			['1.1.1.1', SecurityTxtIpAddressType::V4, true],
			['2001:1337:42:ec00:2468:7ea:cafe:d00d', SecurityTxtIpAddressType::V6, true],
			['127.0.0.1', SecurityTxtIpAddressType::V4, false],
			['192.168.1.1', SecurityTxtIpAddressType::V4, false],
			['10.1.2.3', SecurityTxtIpAddressType::V4, false],
			['::1', SecurityTxtIpAddressType::V6, false],
			['fe80::1ff:fe23:4567:890a', SecurityTxtIpAddressType::V6, false],
			['2001:3f48:2244:344::127.0.0.1', SecurityTxtIpAddressType::V6, false],
			['2001:3f48:2244:344::192.168.1.1', SecurityTxtIpAddressType::V6, false],
			['2001:3f48:2244:344::10.1.2.3', SecurityTxtIpAddressType::V6, false],
			['2001:3f48:2244:344::192.0.2.33', SecurityTxtIpAddressType::V6, false],
			['::ffff:127.0.0.1', SecurityTxtIpAddressType::V6, false],
			['::ffff:192.168.1.1', SecurityTxtIpAddressType::V6, false],
			['::ffff:10.1.2.3', SecurityTxtIpAddressType::V6, false],
			['::ffff:192.0.2.33', SecurityTxtIpAddressType::V6, false],
			['64:ff9b::a9fe:a9fe', SecurityTxtIpAddressType::V6, false], // NAT64 well-known prefix (RFC 6052) embedding 169.254.169.254, rejected
			['64:ff9b::0a00:0001', SecurityTxtIpAddressType::V6, false], // NAT64 well-known prefix embedding 10.0.0.1, rejected
			['64:ff9b::7f00:0001', SecurityTxtIpAddressType::V6, false], // NAT64 well-known prefix embedding 127.0.0.1, rejected
			['64:ff9b::0808:0808', SecurityTxtIpAddressType::V6, true], // NAT64 well-known prefix embedding public 8.8.8.8, allowed (a DNS64 host reaches an IPv4-only site this way)
			['64:ff9b::0101:0101', SecurityTxtIpAddressType::V6, true], // NAT64 well-known prefix embedding public 1.1.1.1, allowed
			['64:ff9b:1::a9fe:a9fe', SecurityTxtIpAddressType::V6, false], // NAT64 local-use prefix (RFC 8215), rejected whole
			['64:ff9b:1::0808:0808', SecurityTxtIpAddressType::V6, false], // NAT64 local-use prefix rejected whole even for a public-embedded target
		];
	}


	/** @dataProvider getIpAddresses */
	public function testValidatePublicIpAddress(string $ipAddress, SecurityTxtIpAddressType $type, bool $isValid): void
	{
		if ($isValid) {
			Assert::noError(function () use ($ipAddress, $type): void {
				$this->validator->validate($ipAddress, $type, $this->host('example.com'), 'https://example.com/');
			});
		} else {
			Assert::throws(function () use ($ipAddress, $type): void {
				$this->validator->validate($ipAddress, $type, $this->host('example.com'), 'https://example.com/');
			}, SecurityTxtHostIpAddressNotPublicException::class, "Host example.com resolves to a non-public IP address {$ipAddress}");
		}
	}


	/**
	 * @return list<array{0:string, 1:SecurityTxtIpAddressType, 2:string}>
	 */
	public function getInvalidIpAddresses(): array
	{
		return [
			['fe80::1ff:fe23:4567:890a%3', SecurityTxtIpAddressType::V6, 'IPv6'],
			['foo', SecurityTxtIpAddressType::V4, 'IPv4'],
			['foo', SecurityTxtIpAddressType::V6, 'IPv6'],
			['1.1.1.0', SecurityTxtIpAddressType::V6, 'IPv6'], // a valid IPv4 address is not a valid IPv6 address
			['2001:1337:42:ec00:2468:7ea:cafe:d00d', SecurityTxtIpAddressType::V4, 'IPv4'], // and vice versa
		];
	}


	/** @dataProvider getInvalidIpAddresses */
	public function testValidateInvalidIpAddress(string $ipAddress, SecurityTxtIpAddressType $type, string $typeLabel): void
	{
		Assert::throws(function () use ($ipAddress, $type): void {
			$this->validator->validate($ipAddress, $type, $this->host('example.com'), 'https://example.com/');
		}, SecurityTxtHostIpAddressInvalidException::class, "Host example.com resolves to an invalid {$typeLabel} address {$ipAddress}");
	}


	/**
	 * @return array<string, array{0:string, 1:SecurityTxtIpAddressType, 2:class-string<SecurityTxtFetcherException>, 3:string}>
	 */
	public function getNonPublicAndInvalid(): array
	{
		return [
			'not public' => ['127.0.0.1', SecurityTxtIpAddressType::V4, SecurityTxtHostIpAddressNotPublicException::class, 'resolves to a non-public IP address 127.0.0.1'],
			'invalid' => ['1.1.1.0', SecurityTxtIpAddressType::V6, SecurityTxtHostIpAddressInvalidException::class, 'resolves to an invalid IPv6 address 1.1.1.0'],
		];
	}


	/**
	 * Both of these name the host, and both took it as a string until now, so an internationalized one was percent encoded here while the same host read as itself in every
	 * other fetch failure. The address is what these are about, but the host is what a reader recognises.
	 *
	 * @param class-string<SecurityTxtFetcherException> $class
	 * @dataProvider getNonPublicAndInvalid
	 */
	public function testAnInternationalizedHostReadsAsItself(string $ipAddress, SecurityTxtIpAddressType $type, string $class, string $expected): void
	{
		$host = "h\u{E1}\u{10D}ky.example";
		// Built out here rather than inside the closure: `host()` throws, and a throw in there would be weighed against the expected class instead of failing outright
		$securityTxtHost = $this->host($host);
		Assert::throws(function () use ($ipAddress, $type, $securityTxtHost, $host): void {
			$this->validator->validate($ipAddress, $type, $securityTxtHost, "https://{$host}/");
		}, $class, "Host {$host} {$expected}");
	}

}

(new SecurityTxtIpAddressValidatorTest())->run();
