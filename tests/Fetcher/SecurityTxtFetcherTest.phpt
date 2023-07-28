<?php
/** @noinspection PhpUnhandledExceptionInspection */
/** @noinspection PhpUnnecessaryFullyQualifiedNameInspection */
/** @noinspection PhpFullyQualifiedNameUsageInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class SecurityTxtFetcherTest extends TestCase
{

	private SecurityTxtFetcher $securityTxtFetcher;


	protected function setUp(): void
	{
		$this->securityTxtFetcher = new SecurityTxtFetcher();
	}


	public function getHeaders(): array
	{
		return [
			'301 redirect with Location' => [
				[
					'HTTP/123.4 301',
					'Foo: bar',
					'Location: https://example.example/example',
				],
				301,
				'https://example.example/example',
			],
			'302 redirect with LOCATION' => [
				[
					'HTTP/123.4 302',
					'Foo: bar',
					'LOCATION: https://example.net/example',
				],
				302,
				'https://example.net/example',
			],
			'Random redirect with location' => [
				[
					'HTTP/123.4 399',
					'Foo: bar',
					'location: https://example.org/example',
				],
				399,
				'https://example.org/example',
			],
			'Success' => [
				[
					'HTTP/123.4 200',
				],
				200,
				null,
			],
			'Random success with nonsensical Location' => [
				[
					'HTTP/123.4 299',
					'Foo: bar',
					'Location: https://example.org/example',
				],
				299,
				'https://example.org/example',
			],
		];
	}


	/**
	 * @param list<string> $metadata
	 * @dataProvider getHeaders
	 */
	public function testGetHttpResponse(array $metadata, int $expectedHttpCode, ?string $expectedLocation): void
	{
		Assert::with($this->securityTxtFetcher, function () use ($metadata, $expectedHttpCode, $expectedLocation): void {
			/** @noinspection PhpUndefinedMethodInspection Closure bound to $this->securityTxtFetcher */
			$headers = $this->getHttpResponse('https://example.com/foo', $metadata, 'contents');
			Assert::same($expectedHttpCode, $headers->getHttpCode());
			Assert::same($expectedLocation, $headers->getHeader('location'));
		});
	}


	public function testGetHttpResponseNoHttpCode(): void
	{
		Assert::with($this->securityTxtFetcher, function (): void {
			Assert::throws(function (): void {
				/** @noinspection PhpUndefinedMethodInspection Closure bound to $this->securityTxtFetcher */
				$this->getHttpResponse('https://example.com/foo', ['Foo/303 808'], 'contents');
			}, SecurityTxtFetcherNoHttpCodeException::class, 'Missing HTTP code when fetching https://example.com/foo');
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
