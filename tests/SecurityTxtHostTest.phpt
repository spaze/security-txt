<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/bootstrap.php';

final class SecurityTxtHostTest extends TestCase
{

	public function testAHostIsBuiltFromTheUrlThatNamesIt(): void
	{
		$host = new SecurityTxtHost(new Url('https://bücher.example/'));
		Assert::same('bücher.example', $host->getUnicode());
		Assert::same('xn--bcher-kva.example', $host->getAscii());
		$host = new SecurityTxtHost(new Url('https://example.com/'));
		Assert::same('example.com', $host->getUnicode());
		Assert::same('example.com', $host->getAscii());
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
			// All or nothing: a label that would read next to one that cannot keeps its punycode too, so the name is the one the URL it came out of reads as. Which labels the
			// decoder decodes irreversibly moves with its version, so these assert the forms agree and the name is not mixed rather than which spelling they agree on
			'mixed, one label reads and one does not' => ['https://xn--bcher-kva.xn--khby.example/', 'xn--bcher-kva.xn--khby.example', null],
			'mixed, decoded out of normalization order' => ['https://xn--wuao.xn--r8jz45g.jp/', 'xn--wuao.xn--r8jz45g.jp', null],
			'decodes out of normalization order' => ['https://xn--wuao.example/', 'xn--wuao.example', null],
			'plain' => ['https://EXAMPLE.com/', 'example.com', 'example.com'],
			'an IPv4 literal' => ['https://1.1.1.1/', '1.1.1.1', '1.1.1.1'],
			'an IPv6 literal' => ['https://[::1]/', '[::1]', '[::1]'],
		];
	}


	/**
	 * One host has one name. The two forms are spellings of it, so whichever is written down settles on the same one. That a name rebuilds the host is asserted
	 * where the rebuilding lives, in `SecurityTxtJsonTest`.
	 *
	 * A name is also never a mix of the two: `Url` serializes a host all decoded or all encoded and has no way to say a mixed one, so a name that mixed them would be a
	 * spelling no URL on that host could ever read as, which is the disagreement one name per host exists to prevent. Asserted for every host here rather than pinned per
	 * case, since which labels the decoder decodes irreversibly moves with its version.
	 *
	 * @param string|null $reads null where the decoder decides the spelling, leaving only the agreement to assert
	 * @dataProvider getHostSpellingsAndNames
	 */
	public function testBothFormsSettleOnOneNameThatIsNeverAMixOfThem(string $url, string $ascii, ?string $reads): void
	{
		$host = new SecurityTxtHost(new Url($url));
		Assert::same($ascii, $host->getAscii());
		if ($reads !== null) {
			Assert::same($reads, $host->getUnicode());
		}
		$name = $host->getUnicode();
		Assert::true($name === $ascii || $name === new Url($url)->getUnicodeHost(), "{$name} is neither what the host reads as nor its A-labels");
	}

}

(new SecurityTxtHostTest())->run();
