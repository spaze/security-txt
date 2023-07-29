<?php
/** @noinspection PhpUnhandledExceptionInspection */
/** @noinspection PhpUnnecessaryFullyQualifiedNameInspection */
/** @noinspection PhpFullyQualifiedNameUsageInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherNoLocationException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class SecurityTxtFetcherTest extends TestCase
{

	private SecurityTxtFetcher $securityTxtFetcher;
	private SecurityTxtFetcherHttpClient $httpClient;


	protected function setUp(): void
	{
		$this->httpClient = new class () implements SecurityTxtFetcherHttpClient {

			private SecurityTxtFetcherResponse $fetcherResponse;


			public function getResponse(string $url, ?string $contextHost): SecurityTxtFetcherResponse
			{
				return $this->fetcherResponse;
			}


			public function setFetcherResponse(SecurityTxtFetcherResponse $fetcherResponse): void
			{
				$this->fetcherResponse = $fetcherResponse;
			}

		};
		$this->securityTxtFetcher = new SecurityTxtFetcher($this->httpClient);
	}


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
				SecurityTxtFetcherNoLocationException::class,
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
	 * @noinspection PhpUndefinedMethodInspection Closure bound to $this->securityTxtFetcher
	 * @noinspection PhpUndefinedFieldInspection Closure bound to $this->securityTxtFetcher
	 */
	public function testGetResponse(int $httpCode, array $headers, int $expectedHttpCode, ?string $expectedLocation, ?string $expectedException): void
	{
		$lowercaseHeaders = [];
		foreach ($headers as $key => $value) {
			$lowercaseHeaders[strtolower($key)] = $value;
		}
		/** @noinspection PhpPossiblePolymorphicInvocationInspection Using an anonymous class with the extra method */
		$this->httpClient->setFetcherResponse(new SecurityTxtFetcherResponse($httpCode, $lowercaseHeaders, 'some random contents'));
		Assert::with($this->securityTxtFetcher, function () use ($headers, $expectedHttpCode, $expectedLocation, $expectedException): void {
			$template = 'https://%s/foo';
			$host = 'host';
			$this->redirects[$this->buildUrl($template, $host)] = [];
			if ($expectedException) {
				Assert::throws(function () use ($template, $host): void {
					$this->getResponse('https://example.com/foo', $template, $host, true);
				}, $expectedException);
			} else {
				$response = $this->getResponse('https://example.com/foo', $template, $host, true);
				Assert::same($expectedHttpCode, $response->getHttpCode());
				Assert::same($expectedLocation, $response->getHeader('location'));
			}
		});
	}


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
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', $wellKnownContents ? new SecurityTxtFetcherResponse(200, [], $wellKnownContents) : null, null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', $topLevelContents ? new SecurityTxtFetcherResponse(200, [], $topLevelContents) : null, null);
		Assert::with($this->securityTxtFetcher, function () use ($wellKnown, $topLevel, $wellKnownWins): void {
			$expected = $wellKnownWins ? $wellKnown->getContents() : $topLevel->getContents();
			/** @noinspection PhpUndefinedMethodInspection Closure bound to $this->securityTxtFetcher */
			Assert::same($expected, $this->getResult($wellKnown, $topLevel)->getContents());
		});
	}


	/**
	 * @throws \Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException Can't read security.txt: foo => 404, bar => 403
	 */
	public function testGetResultNotFound(): void
	{
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', null, new SecurityTxtUrlNotFoundException('foo', 404));
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', null, new SecurityTxtUrlNotFoundException('bar', 403));
		Assert::with($this->securityTxtFetcher, function () use ($wellKnown, $topLevel): void {
			/** @noinspection PhpUndefinedMethodInspection Closure bound to $this->securityTxtFetcher */
			$this->getResult($wellKnown, $topLevel);
		});
	}

}

(new SecurityTxtFetcherTest())->run();
