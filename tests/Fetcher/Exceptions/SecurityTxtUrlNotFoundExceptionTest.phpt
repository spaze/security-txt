<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Json\SecurityTxtJson;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Tester\Assert;
use Tester\TestCase;
use ValueError;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtUrlNotFoundExceptionTest extends TestCase
{

	private SecurityTxtJson $securityTxtJson;


	public function __construct()
	{
		$this->securityTxtJson = new SecurityTxtJson(new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider()));
	}


	public function testGetIpAddressTypeIsACase(): void
	{
		$exception = new SecurityTxtUrlNotFoundException('https://com.example/', 404, '192.0.2.1', SecurityTxtIpAddressType::V4);
		Assert::same('192.0.2.1', $exception->getIpAddress());
		Assert::same(SecurityTxtIpAddressType::V4, $exception->getIpAddressType());
	}


	/**
	 * Through `json_encode()` and `createFetcherExceptionFromJsonValues()` rather than by typing the params out again, so what is asserted is the replay a consumer gets and not
	 * a second copy of the same literals: the params keep the scalar the wire needs, and the getter answers with the case at both ends.
	 */
	public function testTheWireCarriesTheCaseValue(): void
	{
		$exception = new SecurityTxtUrlNotFoundException('https://com.example/', 404, '2001:DB8::1', SecurityTxtIpAddressType::V6);
		$params = $exception->jsonSerialize()['params'];
		assert(is_array($params));
		Assert::same(SecurityTxtIpAddressType::V6->value, $params[3]);

		$encoded = json_encode(['error' => $exception]);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$replayed = $this->securityTxtJson->createFetcherExceptionFromJsonValues($decoded);
		Assert::type(SecurityTxtUrlNotFoundException::class, $replayed);
		assert($replayed instanceof SecurityTxtUrlNotFoundException);
		Assert::same(SecurityTxtIpAddressType::V6, $replayed->getIpAddressType());
		Assert::same('2001:DB8::1', $replayed->getIpAddress());
		Assert::same($exception->jsonSerialize()['params'], $replayed->jsonSerialize()['params']);
	}


	/**
	 * Through the JSON layer because that is where an unchecked value can actually arrive: a literal typed in by hand is refused by static analysis now, so the runtime gate is
	 * only ever reached by a replay of params this library did not write.
	 */
	public function testTheWireCannotForgeATypeOutsideTheEnum(): void
	{
		$e = Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => SecurityTxtUrlNotFoundException::class, 'params' => ['https://com.example/', 404, '192.0.2.1', 1337]]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: Cannot create an object of class ' . SecurityTxtUrlNotFoundException::class);
		Assert::type(ValueError::class, $e?->getPrevious());
		Assert::same('1337 is not a valid backing value for enum ' . SecurityTxtIpAddressType::class, $e?->getPrevious()?->getMessage());
	}

}

(new SecurityTxtUrlNotFoundExceptionTest())->run();
