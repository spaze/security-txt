<?php
/** @noinspection PhpFullyQualifiedNameUsageInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class SecurityTxtUrlParserTest extends TestCase
{

	private SecurityTxtUrlParser $securityTxtUrlParser;


	protected function setUp(): void
	{
		$this->securityTxtUrlParser = new SecurityTxtUrlParser();
	}


	public function getHosts(): array
	{
		return [
			'with scheme' => ['https://example.com', 'example.com'],
			'no scheme' => ['example.com', 'example.com'],
			'relative scheme' => ['//example.com', 'example.com'],
			'scheme with one slash' => ['https:/example.com', 'example.com'],
			'scheme with one slash and a port' => ['https:/example.com:444', 'example.com'],
		];
	}


	/** @dataProvider getHosts */
	public function testGetHostFromUrl(string $input, string $expected): void
	{
		foreach (['', '/', '/foo'] as $path) {
			Assert::same($expected, $this->securityTxtUrlParser->getHostFromUrl($input . $path), $input . $path);
		}
	}


	public function getBadHosts(): array
	{
		return [
			['/example.com'],
		];
	}


	/**
	 * @dataProvider getBadHosts
	 * @throws \Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostnameException
	 */
	public function testGetHostFromUrlBad(string $input): void
	{
		$this->securityTxtUrlParser->getHostFromUrl($input);
	}

}

(new SecurityTxtUrlParserTest())->run();
