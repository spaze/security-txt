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
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\SecurityTxtContentType;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelDiffers;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherTest extends TestCase
{

	private SecurityTxtSplitLines $splitLines;
	private SecurityTxtUrlParser $urlParser;


	public function __construct()
	{
		$this->splitLines = new SecurityTxtSplitLines();
		$this->urlParser = new SecurityTxtUrlParser();
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines);
		$template = 'https://%s/foo';
		$host = 'host';
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', DNS_A, 200, $wellKnownContents !== null ? new SecurityTxtFetcherResponse(200, [], $wellKnownContents, true) : null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', '198.51.100.1', DNS_A, 200, $topLevelContents !== null ? new SecurityTxtFetcherResponse(200, [], $topLevelContents, false) : null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$expected = $wellKnownWins ? $wellKnown->getContents() : $topLevel->getContents();
		$result = $method->invoke($fetcher, $wellKnown, $topLevel, true);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::same($expected, $result->getContents());
		Assert::same($wellKnownWins, $result->isTruncated());
	}


	public function testGetResultGetLine(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', false));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines);
		$lines = ["Contact: 123\n", "Hiring: 456\n"];
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', DNS_A, 200, new SecurityTxtFetcherResponse(200, [], implode('', $lines), false));
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', '198.51.100.1', DNS_A, 200, null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$result = $method->invoke($fetcher, $wellKnown, $topLevel, true);
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('fooUrl', 'fooUrl2', '192.0.2.1', DNS_A, 404, null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('barUrl', 'barUrl2', '198.51.100.1', DNS_A, 403, null);
		$property = new ReflectionProperty($fetcher, 'redirects');
		$fooUrlRedirects = ['https://example.com/foo', 'https://example.net/foo/'];
		$property->setValue($fetcher, ['fooUrl' => $fooUrlRedirects]);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$exception = Assert::throws(function () use ($method, $fetcher, $wellKnown, $topLevel): void {
			$method->invoke($fetcher, $wellKnown, $topLevel, true);
		}, SecurityTxtNotFoundException::class, "Can't read security.txt: fooUrl (192.0.2.1) => 404 (final code after redirects), barUrl (198.51.100.1) => 403");
		assert($exception instanceof SecurityTxtNotFoundException);
		Assert::same(['192.0.2.1' => [DNS_A, 404], '198.51.100.1' => [DNS_A, 403]], $exception->getIpAddresses());
		Assert::same(['fooUrl' => $fooUrlRedirects], $exception->getAllRedirects());
	}


	/**
	 * @return array<string, array{0:string, 1:string, 2:string, 3:string, 4:SecurityTxtTopLevelDiffers|null}>
	 */
	public function getResults(): array
	{
		$finalUrl1 = 'https://final1.example/';
		$finalUrl2 = 'https://final2.example/';
		$contents1 = 'contents1';
		$contents2 = 'contents2';
		return [
			'different final URL, same response' => [$finalUrl1, $finalUrl2, $contents1, $contents1, null],
			'different final URL, different response' => [$finalUrl1, $finalUrl2, $contents1, $contents2, new SecurityTxtTopLevelDiffers($contents1, $contents2)],
			'same final URL, different response' => [$finalUrl1, $finalUrl1, $contents1, $contents2, null],
		];
	}


	/** @dataProvider getResults */
	public function testGetResultTopLevelDiffers(string $finalUrlWellKnown, string $finalUrlTopLevel, string $contentsWellKnown, string $contentsTopLevel, ?SecurityTxtTopLevelDiffers $violation): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'random', false));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines);
		$fetcherResponseWellKnown = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], $contentsWellKnown, false);
		$fetcherResponseTopLevel = new SecurityTxtFetcherResponse(200, [], $contentsTopLevel, false);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('https://url1.example/', $finalUrlWellKnown, '192.0.2.1', DNS_A, 200, $fetcherResponseWellKnown);
		$topLevel = new SecurityTxtFetcherFetchHostResult('https://url2.example/', $finalUrlTopLevel, '198.51.100.1', DNS_A, 200, $fetcherResponseTopLevel);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$result = $method->invoke($fetcher, $wellKnown, $topLevel, true);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::same([], $result->getErrors());
		Assert::equal($violation === null ? [] : [$violation], $result->getWarnings());
	}

}

(new SecurityTxtFetcherTest())->run();
