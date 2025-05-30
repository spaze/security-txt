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
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherTest extends TestCase
{

	private SecurityTxtSplitLines $splitLines;


	public function __construct()
	{
		$this->splitLines = new SecurityTxtSplitLines();
	}


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
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse($httpCode, $lowercaseHeaders, 'some random contents', false));
		$urlParser = new SecurityTxtUrlParser();
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser, $this->splitLines);
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
			Assert::false($response->isTruncated());
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
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', true));
		$urlParser = new SecurityTxtUrlParser();
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser, $this->splitLines);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', DNS_A, $wellKnownContents !== null ? new SecurityTxtFetcherResponse(200, [], $wellKnownContents, true) : null, null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', '198.51.100.1', DNS_A, $topLevelContents !== null ? new SecurityTxtFetcherResponse(200, [], $topLevelContents, false) : null, null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$expected = $wellKnownWins ? $wellKnown->getContents() : $topLevel->getContents();
		$result = $method->invoke($fetcher, $wellKnown, $topLevel);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::same($expected, $result->getContents());
		Assert::same($wellKnownWins, $result->isTruncated());
	}


	public function testGetResultGetLine(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', false));
		$urlParser = new SecurityTxtUrlParser();
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser, $this->splitLines);
		$lines = ["Contact: 123\n", "Hiring: 456\n"];
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', DNS_A, new SecurityTxtFetcherResponse(200, [], implode('', $lines), false), null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', '198.51.100.1', DNS_A, null, null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$result = $method->invoke($fetcher, $wellKnown, $topLevel);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::null($result->getLine(-1)); /** @phpstan-ignore argument.type (Testing invalid line number) */
		Assert::null($result->getLine(0)); /** @phpstan-ignore argument.type (Testing another invalid line number) */
		Assert::same($lines[0], $result->getLine(1));
		Assert::same($lines[1], $result->getLine(2));
		Assert::null($result->getLine(3));
	}


	public function testGetResultNotFound(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', false));
		$urlParser = new SecurityTxtUrlParser();
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser, $this->splitLines);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('fooUrl', 'fooUrl2', '192.0.2.1', DNS_A, null, new SecurityTxtUrlNotFoundException('fooUrl', 404));
		$topLevel = new SecurityTxtFetcherFetchHostResult('barUrl', 'barUrl2', '198.51.100.1', DNS_A, null, new SecurityTxtUrlNotFoundException('barUrl', 403));
		$property = new ReflectionProperty($fetcher, 'redirects');
		$fooUrlRedirects = ['https://example.com/foo', 'https://example.net/foo/'];
		$property->setValue($fetcher, ['fooUrl' => $fooUrlRedirects]);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$exception = Assert::throws(function () use ($method, $fetcher, $wellKnown, $topLevel): void {
			$method->invoke($fetcher, $wellKnown, $topLevel);
		}, SecurityTxtNotFoundException::class, "Can't read security.txt: fooUrl (192.0.2.1) => 404 (final code after redirects), barUrl (198.51.100.1) => 403");
		assert($exception instanceof SecurityTxtNotFoundException);
		Assert::same(['192.0.2.1' => [DNS_A, 404], '198.51.100.1' => [DNS_A, 403]], $exception->getIpAddresses());
		Assert::same(['fooUrl' => $fooUrlRedirects], $exception->getAllRedirects());
	}

}

new SecurityTxtFetcherTest()->run();
