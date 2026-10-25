<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Violations\SecurityTxtCsafWrongFile;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/bootstrap.php';

final class SecurityTxtPrintableValueTest extends TestCase
{

	/**
	 * @return array<string, array{0:string, 1:string}>
	 */
	public function getUrls(): array
	{
		return [
			'readable where decoding is reversible' => ["https://h\u{E1}\u{10D}ky.example/security.txt", "https://h\u{E1}\u{10D}ky.example/security.txt"],
			// `xn--khby` decodes to a pair that composes to one character and encodes back as `xn--jgb`, so the decoded URL would name a host nothing resolved
			'as it resolves where decoding is not' => ['https://xn--khby.example/security.txt', 'https://xn--khby.example/security.txt'],
			'and where only one label of several is' => ['https://xn--bcher-kva.xn--khby.example/x', 'https://xn--bcher-kva.xn--khby.example/x'],
			// Non-ASCII on purpose: an all-ASCII opaque URL renders the same whether or not the scheme is checked, so it would pin nothing
			'a scheme this library does not fetch is printed as given' => ['foo://xn--hky-ela4t.example/x', 'foo://xn--hky-ela4t.example/x'],
			// Its host is case sensitive and decoding one can lose it entirely, `%78n--a` is not punycode and reads back as nothing at all
			'and keeps its host and its case' => ['ftp://%78n--a.EXAMPLE/x', 'ftp://xn--a.EXAMPLE/x'],
			// Pins what the case-sensitive scheme check here relies on: the parser normalises a scheme, so a URL written in any case is still one this library fetches and
			// is rendered by the host rule rather than falling to the arm for schemes it would not
			'a scheme written in any case is still one this library fetches' => ["HtTpS://h\u{E1}\u{10D}ky.example/x", "https://h\u{E1}\u{10D}ky.example/x"],
			'anything already printable is left alone' => ['https://example.com/a%20b', 'https://example.com/a%20b'],
		];
	}


	/**
	 * A URL prints as the host it names. `Url::toUnicodeString()` decodes every punycode label, and decoding is not always reversible, so a URL whose host does not survive it
	 * reads as its A-labels instead: the alternative is a message quoting a URL that resolves somewhere else. `SecurityTxtHost` decides which spelling a host reads as, and
	 * this defers to it rather than keeping a second copy of that rule.
	 *
	 * @dataProvider getUrls
	 */
	public function testAUrlReadsAsTheHostItNames(string $url, string $expected): void
	{
		$parsed = Url::parse($url);
		Assert::notNull($parsed);
		assert($parsed instanceof Url);
		Assert::same($expected, new SecurityTxtPrintableValue($parsed)->render());
	}


	/**
	 * What a printed URL must never do is name a different host than the one it was built from, which is what it did before: `https://xn--khby.example/` printed as
	 * `https://ؤ.example/`, and that resolves to `xn--jgb`.
	 *
	 * A host reads the same way, all of it or none of it, so the URL in a message and the host beside it are the same string on every host, not only on the ones where
	 * every label happens to decode.
	 */
	public function testAPrintedUrlNamesTheHostItWasBuiltFrom(): void
	{
		$names = ['xn--khby.example', 'xn--wuao.example', "h\u{E1}\u{10D}ky.example", 'example.com', 'xn--hky-ela4t.xn--wuao.example', 'xn--bcher-kva.xn--khby.example'];
		foreach ($names as $name) {
			$url = Url::parse("https://{$name}/");
			assert($url instanceof Url);
			$printed = Url::parse(new SecurityTxtPrintableValue($url)->render());
			Assert::notNull($printed, "what was printed for {$name} does not parse");
			Assert::same($url->getAsciiHost(), $printed?->getAsciiHost(), "a URL on {$name} prints as a different host");
		}
	}


	/**
	 * Before PHP 8.5.12 the URL parser copied the two bytes after a `%` that starts no escape into the path unchecked, so a URL in a checked file, a `Canonical` say,
	 * parsed with a control character, an escape sequence or a byte that is not UTF-8 in it. Encoded here, it prints the way a parser that gets it right spells it. Remove
	 * with the encoding once PHP 8.5.12 is required.
	 */
	public function testAUrlTheParserLeftRawBytesInPrintsEncoded(): void
	{
		$rendered = [];
		foreach (["https://example.com/%\x1B[2J", "https://example.com/%\x00x", "https://example.com/%\xFF", "https://example.com/%\xC2\x9B2J"] as $value) {
			$url = Url::parse($value);
			assert($url !== null);
			$rendered[] = new SecurityTxtPrintableValue($url)->render();
		}
		Assert::same(['https://example.com/%%1B[2J', 'https://example.com/%%00x', 'https://example.com/%%FF', 'https://example.com/%%C2%9B2J'], $rendered);
		// Through a violation, which hands a URL from the file over as a `Url` whenever it parses back to itself, and on PHP 8.5.4 this one does
		Assert::same(
			'The file with the Common Security Advisory Framework (CSAF) metadata currently located at https://example.com/%%1B[31mprovider.json must be called provider-metadata.json',
			new SecurityTxtCsafWrongFile("https://example.com/%\x1B[31mprovider.json")->getMessage(),
		);
	}


	/**
	 * A tab is the one character a string can show as `→`, because a string holding that character has it encoded.
	 */
	public function testATabInAStringIsShownAsOneNothingElseCanSpell(): void
	{
		$rendered = [];
		foreach (["Contact:\thttps://example.com/", "a\u{2192}b", 'a\tb', 'a%09b', "a\x0Bb", "a\rb"] as $value) {
			$rendered[$value] = new SecurityTxtPrintableValue($value)->render();
		}
		Assert::same([
			"Contact:\thttps://example.com/" => 'Contact:→https://example.com/',
			"a\u{2192}b" => 'a%E2%86%92b',
			'a\tb' => 'a\tb',
			'a%09b' => 'a%09b',
			"a\x0Bb" => 'a%0Bb',
			"a\rb" => 'a%0Db',
		], $rendered);
	}

}

new SecurityTxtPrintableValueTest()->run();
