<?php
/** @noinspection PhpFullyQualifiedNameUsageInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

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
	 * @return array<string, array{0:string, 1:string, 2:int|null}>
	 */
	public function getUrls(): array
	{
		return [
			'with scheme' => ['https://example.com', 'example.com', null],
			'no scheme' => ['example.com', 'example.com', null],
			'relative scheme' => ['//example.com', 'example.com', null],
			'scheme with one slash' => ['https:/example.com', 'example.com', null],
			'scheme with one slash and a port' => ['https:/example.com:444', 'example.com', 444],
			'no scheme with one slash' => ['/example.com', 'example.com', null],
			'no scheme three slashes' => ['///example.com', 'example.com', null],
			'no scheme four slashes' => ['////example.com', 'example.com', null],
			'with scheme mixed case' => ['https://EXAMPLE.com', 'example.com', null],
			'no scheme mixed case' => ['EXAMPLE.com', 'example.com', null],
			'relative scheme mixed case' => ['//EXAMPLE.com', 'example.com', null],
			'scheme with one slash mixed case' => ['https:/EXAMPLE.com', 'example.com', null],
			'scheme with one slash and a port mixed case' => ['https:/EXAMPLE.com:444', 'example.com', 444],
			'IPv4 address' => ['https://192.0.2.1/foo', '192.0.2.1', null],
			'IPv6 address' => ['https://[2001:db8::1]/foo', '[2001:db8::1]', null],
			'with scheme with port' => ['https://example.com:4433', 'example.com', 4433],
			'with scheme with default port' => ['https://example.com:443', 'example.com', null],
		];
	}


	/** @dataProvider getUrls */
	public function testGetUrl(string $input, string $expectedHost, ?int $expectedPort): void
	{
		foreach (['', '/', '/foo'] as $path) {
			$url = $this->securityTxtUrlParser->getUrl($input . $path);
			Assert::same($expectedHost, $url->getUnicodeHost(), $input . $path);
			Assert::same($expectedPort, $url->getPort(), $input . $path);
		}
	}


	/**
	 * @return array<string, array{0:string}>
	 */
	public function getBadUrls(): array
	{
		return [
			'empty string' => [''],
			'space' => [' '],
			'scheme:' => ['https:'],
			'scheme://' => ['https://'],
			'no scheme with port' => ['example.com:4433'],
		];
	}


	/**
	 * @dataProvider getBadUrls
	 */
	public function testGetUrlBad(string $input): void
	{
		Assert::throws(function () use ($input): void {
			$this->securityTxtUrlParser->getUrl($input);
		}, SecurityTxtCannotParseHostnameException::class);
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
			['../new1/new2', 'https://example.com/foo/bar.ext', 'https://example.com/new1/new2'],
			['../new1/new2', 'https://example.com/', 'https://example.com/new1/new2'],
			['/../new1/new2', 'https://example.com/foo/bar.ext', 'https://example.com/new1/new2'],
			['/../new1/new2', 'https://example.com/', 'https://example.com/new1/new2'],
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
			['//new.test/new', 'https://example.com/bar', 'https://new.test/new'],
			['https://new.test', 'https://example.com/bar', 'https://new.test/'],
			[':', 'https://example.com/foo', 'https://example.com/:'],
			['?bar', 'https://example.com/foo/file.ext', 'https://example.com/foo/file.ext?bar'],
			['?bar', 'https://example.com', 'https://example.com/?bar'],
			['/new', 'https://example.org:1337/foo', 'https://example.org:1337/new'],
			['file:///etc/passwd', 'https://example.org/foo', 'file:///etc/passwd'],
			['file://./etc/passwd', 'https://example.org/foo', 'file://./etc/passwd'],
			['file://../etc/passwd', 'https://example.org/foo', 'file://../etc/passwd'],
			['file://foo/etc/passwd', 'https://example.org/foo', 'file://foo/etc/passwd'],
			['scheme://foo-bar', 'https://example.org/foo', 'scheme://foo-bar'],
		];
	}


	/**
	 * @dataProvider getRedirects
	 */
	public function testGetRedirectUrl(string $location, string $url, string $expected): void
	{
		$currentUrl = Url::parse($url);
		assert(isset($currentUrl));
		Assert::same($expected, $this->securityTxtUrlParser->getRedirectUrl($location, $currentUrl)->toUnicodeString());
	}


	/**
	 * @return list<array{0:string}>
	 */
	public function getBadCurrentUrls(): array
	{
		return [
			[':'],
			['foo'],
		];
	}


	/**
	 * @dataProvider getBadCurrentUrls
	 */
	public function testGetRedirectBadCurrentUrl(string $url): void
	{
		Assert::null(Url::parse($url));
	}

}

(new SecurityTxtUrlParserTest())->run();
