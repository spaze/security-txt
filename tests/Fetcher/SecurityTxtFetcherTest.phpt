<?php
/** @noinspection PhpUnnecessaryFullyQualifiedNameInspection */
/** @noinspection PhpFullyQualifiedNameUsageInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

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
				'https://example.example/example',
			],
			'301 redirect with LOCATION' => [
				[
					'HTTP/123.4 302',
					'Foo: bar',
					'LOCATION: https://example.net/example',
				],
				'https://example.net/example',
			],
			'Random redirect with location' => [
				[
					'HTTP/123.4 399',
					'Foo: bar',
					'location: https://example.org/example',
				],
				'https://example.org/example',
			],
			'Success' => [
				[
					'HTTP/123.4 200',
				],
				null,
			],
			'Random success with nonsensical Location' => [
				[
					'HTTP/123.4 299',
					'Foo: bar',
					'Location: https://example.org/example',
				],
				null,
			],
		];
	}


	/**
	 * @param array<int, string> $headers
	 * @param string|null $expected
	 * @dataProvider getHeaders
	 */
	public function testGetLocation(array $headers, ?string $expected): void
	{
		Assert::with($this->securityTxtFetcher, function () use ($headers, $expected): void {
			/** @noinspection PhpUndefinedMethodInspection Closure bound to $this->securityTxtFetcher */
			Assert::same($expected, $this->getLocation('https://example.com/foo', $headers));
		});
	}


	public function getStatusCodes(): array
	{
		return [
			'400' => [400],
			'401' => [401],
			'403' => [403],
			'404' => [404],
			'500' => [500],
			'503' => [503],
			'999' => [999],
			'1234' => [1234],
		];
	}


	/**
	 * @param int $statusCode
	 * @dataProvider getStatusCodes
	 * @throws \Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException
	 */
	public function testGetLocationException(int $statusCode): void
	{
		Assert::with($this->securityTxtFetcher, function () use ($statusCode): void {
			/** @noinspection PhpUndefinedMethodInspection Closure bound to $this->securityTxtFetcher */
			$this->getLocation('https://example.com/foo', ["HTTP/1.1 {$statusCode} Something"]);
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
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', $wellKnownContents, null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', $topLevelContents, null);
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
