<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/bootstrap.php';

/** @testCase */
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
		Assert::same($expected, SecurityTxtPrintableValue::render($parsed));
	}


	/**
	 * What a printed URL must never do is name a different host than the one it was built from, which is what it did before: `https://xn--khby.example/` printed as
	 * `https://ؤ.example/`, and that resolves to `xn--jgb`.
	 *
	 * It is not the same as reading letter for letter like the host does. A host decodes label by label, so `xn--hky-ela4t.xn--wuao.example` reads as
	 * `háčky.xn--wuao.example`, while a URL falls back to its A-labels whole as soon as any label does not survive decoding. Both name the host that was resolved, which is
	 * the property worth having; the URL is just less decoded than it could be.
	 */
	public function testAPrintedUrlNamesTheHostItWasBuiltFrom(): void
	{
		$names = ['xn--khby.example', 'xn--wuao.example', "h\u{E1}\u{10D}ky.example", 'example.com', 'xn--hky-ela4t.xn--wuao.example', 'xn--bcher-kva.xn--khby.example'];
		foreach ($names as $name) {
			$url = Url::parse("https://{$name}/");
			assert($url instanceof Url);
			$printed = Url::parse(SecurityTxtPrintableValue::render($url));
			Assert::notNull($printed, "what was printed for {$name} does not parse");
			Assert::same($url->getAsciiHost(), $printed?->getAsciiHost(), "a URL on {$name} prints as a different host");
		}
	}

}

new SecurityTxtPrintableValueTest()->run();
