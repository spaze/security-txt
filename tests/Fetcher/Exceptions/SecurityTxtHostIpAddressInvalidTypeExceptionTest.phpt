<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidTypeException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtHostIpAddressInvalidTypeExceptionTest extends TestCase
{

	public function testGetters(): void
	{
		$exception = new SecurityTxtHostIpAddressInvalidTypeException('example.com', 'coconut', 'https://example.com/');
		Assert::same('IP address of example.com is a coconut, should be a string', $exception->getMessage());
	}

}

(new SecurityTxtHostIpAddressInvalidTypeExceptionTest())->run();
