<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotPublicException;
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
		];
	}


	/** @dataProvider getIpAddresses */
	public function testValidatePublicIpAddress(string $ipAddress, SecurityTxtIpAddressType $type, bool $isValid): void
	{
		if ($isValid) {
			Assert::noError(function () use ($ipAddress, $type): void {
				$this->validator->validate($ipAddress, $type, 'example.com', 'https://example.com/');
			});
		} else {
			Assert::throws(function () use ($ipAddress, $type): void {
				$this->validator->validate($ipAddress, $type, 'example.com', 'https://example.com/');
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
			$this->validator->validate($ipAddress, $type, 'example.com', 'https://example.com/');
		}, SecurityTxtHostIpAddressInvalidException::class, "Host example.com resolves to an invalid {$typeLabel} address {$ipAddress}");
	}

}

(new SecurityTxtIpAddressValidatorTest())->run();
