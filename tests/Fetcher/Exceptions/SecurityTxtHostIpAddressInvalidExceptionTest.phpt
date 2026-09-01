<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Json\SecurityTxtJson;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxtHost;
use Tester\Assert;
use Tester\TestCase;
use ValueError;

require __DIR__ . '/../../bootstrap.php';

/**
 * The constructor takes only a case now; the wire's int comes back through `SecurityTxtJson`, which turns it into a case before calling, so the gate that refuses a value
 * outside the enum lives there and is reached through a replay.
 *
 * @testCase
 */
final class SecurityTxtHostIpAddressInvalidExceptionTest extends TestCase
{

	private SecurityTxtJson $securityTxtJson;


	public function __construct()
	{
		$this->securityTxtJson = new SecurityTxtJson(new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider()));
	}


	/**
	 * @return array<string, array{0:SecurityTxtIpAddressType, 1:string, 2:string}>
	 */
	public function getTypes(): array
	{
		return [
			'IPv4' => [SecurityTxtIpAddressType::V4, '192.0.2.1', 'IPv4'],
			'IPv6' => [SecurityTxtIpAddressType::V6, '2001:DB8::1', 'IPv6'],
		];
	}


	/**
	 * The case and the value it arrives as on the wire have to name the same family, which is what went wrong before: anything that was not `V4` was called IPv6.
	 *
	 * @dataProvider getTypes
	 */
	public function testTheCaseAndItsWireValueNameTheSameFamily(SecurityTxtIpAddressType $type, string $ip, string $label): void
	{
		$fromCase = new SecurityTxtHostIpAddressInvalidException(SecurityTxtHost::fromString("h\u{E1}\u{10D}ky.example"), $ip, $type, 'https://com.example/');
		Assert::contains("resolves to an invalid {$label} address", $fromCase->getMessage());
		Assert::same($type, $fromCase->getIpAddressType());

		$encoded = json_encode(['error' => $fromCase]);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$replayed = $this->securityTxtJson->createFetcherExceptionFromJsonValues($decoded);
		Assert::type(SecurityTxtHostIpAddressInvalidException::class, $replayed);
		assert($replayed instanceof SecurityTxtHostIpAddressInvalidException);
		Assert::same($type, $replayed->getIpAddressType());
		Assert::same($fromCase->getMessage(), $replayed->getMessage());
		Assert::same($fromCase->jsonSerialize()['params'], $replayed->jsonSerialize()['params']);
	}


	public function testTheWireCarriesTheCaseValueNotTheCase(): void
	{
		$exception = new SecurityTxtHostIpAddressInvalidException(SecurityTxtHost::fromString("h\u{E1}\u{10D}ky.example"), '2001:DB8::1', SecurityTxtIpAddressType::V6, 'https://com.example/');
		$params = $exception->jsonSerialize()['params'];
		assert(is_array($params));
		Assert::same(SecurityTxtIpAddressType::V6->value, $params[2]);
	}


	/**
	 * Through the JSON layer because that is where an unchecked value can actually arrive: a literal typed in by hand is refused by static analysis now, so the runtime gate is
	 * only ever reached by a replay of params this library did not write.
	 */
	public function testTheWireCannotForgeATypeOutsideTheEnum(): void
	{
		$e = Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => SecurityTxtHostIpAddressInvalidException::class, 'params' => ["h\u{E1}\u{10D}ky.example", '192.0.2.1', 1337, 'https://com.example/']]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: Cannot create an object of class ' . SecurityTxtHostIpAddressInvalidException::class);
		Assert::type(ValueError::class, $e?->getPrevious());
		Assert::same('1337 is not a valid backing value for enum ' . SecurityTxtIpAddressType::class, $e?->getPrevious()?->getMessage());
	}

}

(new SecurityTxtHostIpAddressInvalidExceptionTest())->run();
