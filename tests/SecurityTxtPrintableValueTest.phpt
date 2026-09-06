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
			'a scheme this library does not fetch is encoded whole' => ['foo://Plain.Example/x', 'foo://plain.example/x'],
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
	 * The rule is the host's, so the two cannot disagree about the same host, which is what they did before: a URL said `ؤ.example` where the host said `xn--khby.example`.
	 */
	public function testAUrlAndAHostAgreeAboutTheSameHost(): void
	{
		foreach (['xn--khby.example', 'xn--wuao.example', "h\u{E1}\u{10D}ky.example", 'example.com'] as $name) {
			$url = Url::parse("https://{$name}/");
			assert($url instanceof Url);
			$rendered = SecurityTxtPrintableValue::render($url);
			$host = SecurityTxtPrintableValue::render(new SecurityTxtHost($url));
			Assert::contains($host, $rendered, "a URL on {$name} does not read as the host does");
		}
	}

}

new SecurityTxtPrintableValueTest()->run();
