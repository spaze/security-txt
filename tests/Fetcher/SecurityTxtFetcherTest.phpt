<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Override;
use ReflectionMethod;
use ReflectionProperty;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoLocationHeaderException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherTest extends TestCase
{

	private function getHttpClient(SecurityTxtFetcherResponse $fetcherResponse): SecurityTxtFetcherHttpClient
	{
		return new readonly class ($fetcherResponse) implements SecurityTxtFetcherHttpClient {

			public function __construct(private SecurityTxtFetcherResponse $fetcherResponse)
			{
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, ?string $contextHost): SecurityTxtFetcherResponse
			{
				return $this->fetcherResponse;
			}

		};
	}


	/**
	 * @return array<string, array{0:int, 1:array<string, string>, 2:int, 3:string|null, 4:class-string<SecurityTxtFetcherException>|null}>
	 */
	public function getHeaders(): array
	{
		return [
			'301 redirect with Location' => [
				301,
				[
					'Foo' => 'bar',
					'Location' => 'https://example.example/example',
				],
				301,
				null,
				SecurityTxtTooManyRedirectsException::class, // The only way to test redirects is to catch en exception
			],
			'302 redirect with no Location' => [
				302,
				[
					'Foo' => 'bar',
				],
				302,
				null,
				SecurityTxtNoLocationHeaderException::class,
			],
			'Random redirect with location' => [
				399,
				[
					'Foo' => 'bar',
					'location' => 'https://example.org/example',
				],
				399,
				null,
				SecurityTxtTooManyRedirectsException::class, // The only way to test redirects is to catch en exception
			],
			'Success' => [
				200,
				[],
				200,
				null,
				null,
			],
			'Random success with nonsensical Location' => [
				299,
				[
					'Foo' => 'bar',
					'Location' => 'https://example.org/example',
				],
				299,
				'https://example.org/example',
				null,
			],
		];
	}


	/**
	 * @param array<string, string> $headers
	 * @param class-string<SecurityTxtFetcherException>|null $expectedException
	 * @dataProvider getHeaders
	 */
	public function testGetResponse(int $httpCode, array $headers, int $expectedHttpCode, ?string $expectedLocation, ?string $expectedException): void
	{
		$lowercaseHeaders = [];
		foreach ($headers as $key => $value) {
			$lowercaseHeaders[strtolower($key)] = $value;
		}
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse($httpCode, $lowercaseHeaders, 'some random contents'));
		$urlParser = new SecurityTxtUrlParser();
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser);
		$template = 'https://%s/foo';
		$host = 'host';
		$property = new ReflectionProperty($fetcher, 'redirects');
		$redirects = $property->getValue($fetcher);
		assert(is_array($redirects));
		$property->setValue($fetcher, array_merge($redirects, [sprintf($template, $host) => []]));
		$method = new ReflectionMethod($fetcher, 'getResponse');
		$finalUrl = 'passed by ref';
		if ($expectedException !== null) {
			Assert::throws(function () use ($method, $fetcher, $template, $host, $finalUrl): void {
				$method->invokeArgs($fetcher, ['https://example.com/foo', $template, $host, true, &$finalUrl]);
			}, $expectedException);
		} else {
			$response = $method->invokeArgs($fetcher, ['https://example.com/foo', $template, $host, true, &$finalUrl]);
			assert($response instanceof SecurityTxtFetcherResponse);
			Assert::same($expectedHttpCode, $response->getHttpCode());
			Assert::same($expectedLocation, $response->getHeader('location'));
		}
	}


	/**
	 * @return array<string, array{0:string|null, 1:string|null, 2:bool}>
	 */
	public function getContents(): array
	{
		return [
			'both 200' => ['well-known', 'top-level', true],
			'top-level 404' => ['well-known', null, true],
			'well-known 404' => [null, 'top-level', false],
			'same' => ['same', 'same', true],
		];
	}


	/** @dataProvider getContents */
	public function testGetResult(?string $wellKnownContents, ?string $topLevelContents, bool $wellKnownWins): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents'));
		$urlParser = new SecurityTxtUrlParser();
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', $wellKnownContents !== null ? new SecurityTxtFetcherResponse(200, [], $wellKnownContents) : null, null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', $topLevelContents !== null ? new SecurityTxtFetcherResponse(200, [], $topLevelContents) : null, null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$expected = $wellKnownWins ? $wellKnown->getContents() : $topLevel->getContents();
		$result = $method->invoke($fetcher, $wellKnown, $topLevel);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::same($expected, $result->getContents());
	}


	public function testGetResultNotFound(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents'));
		$urlParser = new SecurityTxtUrlParser();
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', null, new SecurityTxtUrlNotFoundException('foo', 404));
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', null, new SecurityTxtUrlNotFoundException('bar', 403));
		$method = new ReflectionMethod($fetcher, 'getResult');
		Assert::throws(function () use ($method, $fetcher, $wellKnown, $topLevel): void {
			$method->invoke($fetcher, $wellKnown, $topLevel);
		}, SecurityTxtNotFoundException::class, "Can't read `security.txt`: `foo` => `404`, `bar` => `403`");
	}

}

new SecurityTxtFetcherTest()->run();
