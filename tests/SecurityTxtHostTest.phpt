<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/bootstrap.php';

/** @testCase */
final class SecurityTxtHostTest extends TestCase
{

	public function testFromStringAcceptsOnlyTheSerializedForm(): void
	{
		$host = SecurityTxtHost::fromString('bücher.example');
		Assert::same('bücher.example', $host->getUnicode());
		Assert::same('xn--bcher-kva.example', $host->getAscii());
		$host = SecurityTxtHost::fromString('example.com');
		Assert::same('example.com', $host->getUnicode());
		Assert::same('example.com', $host->getAscii());
	}


	public function testFromStringRefusesWhatWouldBeSilentlyRewritten(): void
	{
		// Would read back as the IP address 0.0.3.40
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('808');
		}, SecurityTxtCannotParseHostnameException::class);
		// A valid spelling of a host, but not one getUnicode() ever writes, would read back as bücher.example
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('xn--bcher-kva.example');
		}, SecurityTxtCannotParseHostnameException::class);
		// Would read back lowercased
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('Example.COM');
		}, SecurityTxtCannotParseHostnameException::class);
		// A URL, not a host, would read back without the path
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('https://example.com/');
		}, SecurityTxtCannotParseHostnameException::class);
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('not a hostname');
		}, SecurityTxtCannotParseHostnameException::class);
	}


	public function testBothSpellingsOfAHostAskForTheSameName(): void
	{
		// Whichever way a host was written, the ASCII form is what goes to the resolver and onto the wire, so both spellings have to arrive at the same one
		$readable = new SecurityTxtHost(new Url("https://h\u{E1}\u{10D}ky\u{10D}\u{E1}rky.cz/"));
		$punycode = new SecurityTxtHost(new Url('https://xn--hkyrky-ptac70bc.cz/'));
		Assert::same('xn--hkyrky-ptac70bc.cz', $readable->getAscii());
		Assert::same($readable->getAscii(), $punycode->getAscii());
		Assert::same($readable->getUnicode(), $punycode->getUnicode());
	}


	public function testAnOpaqueHostIsKeptAsWhateverParsingMadeOfIt(): void
	{
		// A scheme WHATWG calls special, FTP among them, runs IDNA like HTTPS does, so those hosts read as themselves; one it calls opaque does not run IDNA and its host is
		// case sensitive, so decoding it would name a different host and the host reads as what was written instead
		$fromFtp = new SecurityTxtHost(new Url('ftp://bücher.example'));
		Assert::same('bücher.example', $fromFtp->getUnicode());
		Assert::same('xn--bcher-kva.example', $fromFtp->getAscii());
		$opaque = new SecurityTxtHost(new Url('foo://Plain.Example/x'));
		Assert::same('Plain.Example', $opaque->getUnicode());
		Assert::same('Plain.Example', $opaque->getAscii());
		// Still refused as a string, because a string is parsed under HTTPS, where that host reads as `plain.example`
		Assert::throws(function () use ($opaque): void {
			SecurityTxtHost::fromString($opaque->getUnicode());
		}, SecurityTxtCannotParseHostnameException::class);
	}


	/**
	 * @return array<string, array{0:string}>
	 */
	public function getUrlsWithAHostItCannotStandBehind(): array
	{
		return [
			'a file URL' => ['file:///x'],
			'a label that is not valid punycode' => ['https://%78n--a.example/'],
			// Not settled: parsing decodes the escape without folding the case it uncovers, so this host would read as `exAmple.com`, a spelling it cannot be rebuilt from.
			// `SecurityTxtUrlParser::normalize()` is what a caller settles with
			'a URL that has not been settled' => ['https://ex%41mple.com/'],
			'another that has not been settled' => ['https://%41%42.example/'],
		];
	}


	/**
	 * A host this class cannot stand behind: one that resolves to nothing, and one taken from a URL that has not been settled, which would read as a spelling it cannot be
	 * rebuilt from. Both are refused rather than built and left to fail somewhere further along.
	 *
	 * @dataProvider getUrlsWithAHostItCannotStandBehind
	 */
	public function testAHostItCannotStandBehindIsRefused(string $url): void
	{
		Assert::throws(function () use ($url): void {
			new SecurityTxtHost(new Url($url));
		}, SecurityTxtCannotParseHostnameException::class);
	}


	/**
	 * @return array<string, array{0:string, 1:string, 2:string|null}>
	 */
	public function getHostSpellingsAndNames(): array
	{
		return [
			// Both spellings of one host converge on one name
			'readable' => ["https://h\u{E1}\u{10D}ky.example/", 'xn--hky-ela4t.example', "h\u{E1}\u{10D}ky.example"],
			'the same host in punycode' => ['https://xn--hky-ela4t.example/', 'xn--hky-ela4t.example', "h\u{E1}\u{10D}ky.example"],
			'japanese, readable' => ["https://\u{4F8B}\u{3048}.jp/", 'xn--r8jz45g.jp', "\u{4F8B}\u{3048}.jp"],
			'japanese, punycode' => ['https://xn--r8jz45g.jp/', 'xn--r8jz45g.jp', "\u{4F8B}\u{3048}.jp"],
			// A label whose decoded form encodes back as a different host reads as what was written. Which labels ICU decodes that way moves with its version, so these assert
			// that the two forms agree rather than which spelling they agree on
			'decodes to a different host' => ['https://xn--khby.example/', 'xn--khby.example', null],
			// Decided per label: the readable label reads decoded next to one that keeps its punycode, whether the decoder decodes that one irreversibly or leaves it be
			'mixed, decoded next to punycode' => ['https://xn--bcher-kva.xn--khby.example/', 'xn--bcher-kva.xn--khby.example', "b\u{FC}cher.xn--khby.example"],
			// Judged in place: decoded `xn--wuao` re-encodes as itself alone but as `xn--wuan` beside a neighbour, so trusting the lone label would decode it into a name that
			// rebuilds a different host, and this pins that its neighbour still reads decoded
			'mixed, in-place beats alone' => ['https://xn--wuao.xn--r8jz45g.jp/', 'xn--wuao.xn--r8jz45g.jp', "xn--wuao.\u{4F8B}\u{3048}.jp"],
			'decodes out of normalization order' => ['https://xn--wuao.example/', 'xn--wuao.example', null],
			'plain' => ['https://EXAMPLE.com/', 'example.com', 'example.com'],
			'an IPv4 literal' => ['https://1.1.1.1/', '1.1.1.1', '1.1.1.1'],
			'an IPv6 literal' => ['https://[::1]/', '[::1]', '[::1]'],
		];
	}


	/**
	 * One host has one name. The two forms are spellings of it, so whichever is written down has to encode back to the same host, and what a host reads as has to be what it can
	 * be rebuilt from, which is what a stored result depends on.
	 *
	 * @param string|null $reads null where ICU's decode decides the spelling, leaving only the agreement to assert
	 * @dataProvider getHostSpellingsAndNames
	 */
	public function testBothFormsNameTheSameHostAndRebuildIt(string $url, string $ascii, ?string $reads): void
	{
		$host = new SecurityTxtHost(new Url($url));
		Assert::same($ascii, $host->getAscii());
		if ($reads !== null) {
			Assert::same($reads, $host->getUnicode());
		}
		Assert::same($ascii, SecurityTxtHost::fromString($host->getUnicode())->getAscii());
	}

}

(new SecurityTxtHostTest())->run();
