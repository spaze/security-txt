<?php
/** @noinspection PhpFullyQualifiedNameUsageInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtUrlParserTest extends TestCase
{

	private SecurityTxtUrlParser $securityTxtUrlParser;


	public function __construct()
	{
		$this->securityTxtUrlParser = new SecurityTxtUrlParser();
	}


	/**
	 * @return array<string, array{0:string, 1:string}>
	 */
	public function getHosts(): array
	{
		return [
			'with scheme' => ['https://example.com', 'example.com'],
			'no scheme' => ['example.com', 'example.com'],
			'relative scheme' => ['//example.com', 'example.com'],
			'scheme with one slash' => ['https:/example.com', 'example.com'],
			'scheme with one slash and a port' => ['https:/example.com:444', 'example.com'],
			'with scheme mixed case' => ['https://EXAMPLE.com', 'example.com'],
			'no scheme mixed case' => ['EXAMPLE.com', 'example.com'],
			'relative scheme mixed case' => ['//EXAMPLE.com', 'example.com'],
			'scheme with one slash mixed case' => ['https:/EXAMPLE.com', 'example.com'],
			'scheme with one slash and a port mixed case' => ['https:/EXAMPLE.com:444', 'example.com'],
		];
	}


	/** @dataProvider getHosts */
	public function testGetHostFromUrl(string $input, string $expected): void
	{
		foreach (['', '/', '/foo'] as $path) {
			Assert::same($expected, $this->securityTxtUrlParser->getHostFromUrl($input . $path), $input . $path);
		}
	}


	/**
	 * @return list<array{0:string}>
	 */
	public function getBadHosts(): array
	{
		return [
			['/example.com'],
		];
	}


	/**
	 * @dataProvider getBadHosts
	 * @throws \Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException
	 */
	public function testGetHostFromUrlBad(string $input): void
	{
		$this->securityTxtUrlParser->getHostFromUrl($input);
	}


	/**
	 * @return list<array{0:string, 1:string, 2:string}>
	 */
	public function getRedirects(): array
	{
		return [
			['/new', 'https://example.com/bar', 'https://example.com/new'],
			['new', 'https://example.com/bar', 'https://example.com/new'],
			['/new', 'https://example.com/foo/bar', 'https://example.com/new'],
			['new', 'https://example.com/foo/bar', 'https://example.com/foo/new'],
			['new', 'https://example.com/foo/bar.ext', 'https://example.com/foo/new'],
			['/new1/new2', 'https://example.com/foo/bar/baz', 'https://example.com/new1/new2'],
			['/new1/new2', 'https://example.com/foo/bar.ext', 'https://example.com/new1/new2'],
			['new1/new2', 'https://example.com/foo/bar.ext', 'https://example.com/foo/new1/new2'],
			['/', 'https://example.com/foo/bar', 'https://example.com/'],
			['../new1/new2', 'https://example.com/foo/bar.ext', 'https://example.com/foo/../new1/new2'],
			['../new1/new2', 'https://example.com/', 'https://example.com/../new1/new2'],
			['/../new1/new2', 'https://example.com/foo/bar.ext', 'https://example.com/../new1/new2'],
			['/../new1/new2', 'https://example.com/', 'https://example.com/../new1/new2'],
			['/new1/new2/new3', 'https://example.com/foo/bar.ext', 'https://example.com/new1/new2/new3'],
			['/new1/new2?new=query', 'https://example.com/foo/bar/baz', 'https://example.com/new1/new2?new=query'],
			['/new1/new2?new=query', 'https://example.com/foo/bar/baz?old=query', 'https://example.com/new1/new2?new=query'],
			['/new1/new2?new=query', 'https://example.com/foo/bar/baz?old=query', 'https://example.com/new1/new2?new=query'],
			['/new1/new2#fragment', 'https://example.com/foo/bar/baz', 'https://example.com/new1/new2#fragment'],
			['/new1/new2#fragment', 'https://example.com/foo/bar/baz?old=query#frag', 'https://example.com/new1/new2#fragment'],
			['/new1/new2', 'https://example.com/foo/bar/baz#frag', 'https://example.com/new1/new2'],
			['/new1/new2?new=query#fragment', 'https://example.com/foo/bar/baz?old=query#frag', 'https://example.com/new1/new2?new=query#fragment'],
			['/new1/new2', 'https://example.com/foo/bar/baz?old=query#frag', 'https://example.com/new1/new2'],
			['https://new.test/new', 'https://example.com/bar', 'https://new.test/new'],
			['https://new.test/new', 'https://example.com:303/bar', 'https://new.test/new'],
			['https://new.test:808/new', 'https://example.com/bar', 'https://new.test:808/new'],
			['https://new.test/new?query', 'https://example.com/bar', 'https://new.test/new?query'],
			['https://new.test/new?query#fragment', 'https://example.com/bar', 'https://new.test/new?query#fragment'],
			['//new.test/new', 'https://example.com/bar', '//new.test/new'], // up to the client to deal with an empty scheme
			['https://new.test', 'https://example.com/bar', 'https://new.test'], // up to the client to deal with an empty path
			[':', 'https://example.com/foo', ':'], // the new location can't be parsed but still go with it
			['/new', ':', '/new'],
			['?bar', 'https://example.com/foo/file.ext', 'https://example.com/foo/file.ext?bar'],
			['?bar', 'https://example.com', 'https://example.com/?bar'],
			['/new', 'https://example.org:1337/foo', 'https://example.org:1337/new'],
		];
	}


	/**
	 * @dataProvider getRedirects
	 */
	public function testGetRedirectUrl(string $location, string $url, string $expected): void
	{
		Assert::same($expected, $this->securityTxtUrlParser->getRedirectUrl($location, $url));
	}

}

(new SecurityTxtUrlParserTest())->run();
