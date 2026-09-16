<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use LogicException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

final class SecurityTxtJsonValueFactoryTest extends TestCase
{

	/**
	 * By the test the parser names a file not UTF-8 by, which agrees with `json_encode()` on every byte.
	 */
	public function testAStringGoesAsBase64ExactlyWhenJsonCannotWriteIt(): void
	{
		$factory = new SecurityTxtJsonValueFactory();
		$strings = ['', "\0", 'Expires', "Michal \u{160}pa\u{10D}ek", "Michal \xA9pa\xE8ek", "\xED\xA0\x80", "\xF4\x90\x80\x80", "\xC0\x80"];
		for ($byte = 0; $byte < 256; $byte++) {
			$strings[] = chr($byte);
		}
		$base64 = 0;
		foreach ($strings as $string) {
			$expected = json_encode($string) === false ? ['contentsBase64' => base64_encode($string)] : ['contents' => $string];
			$entry = $factory->create('contents', $string);
			Assert::same($expected, [$entry->getKey() => $entry->getValue()], bin2hex($string));
			$base64 += isset($expected['contentsBase64']) ? 1 : 0;
		}
		Assert::same(128 + 4, $base64); // The bytes 0x80 to 0xFF on their own, a Latin-2 name, a surrogate, a code point past U+10FFFF and an overlong NUL
	}


	/**
	 * One string JSON cannot write takes the whole list with it, at any depth; a key is refused instead, it is what a value is found by.
	 */
	public function testAListGoesAsBase64WholeWhenOneStringInItCannotBeWritten(): void
	{
		$factory = new SecurityTxtJsonValueFactory();
		$plain = $factory->create('params', ['Expires', 400, ['url' => 'Contact', null]]);
		Assert::same(['params' => ['Expires', 400, ['url' => 'Contact', null]]], [$plain->getKey() => $plain->getValue()]);
		$base64 = $factory->create('params', ['Expires', 400, ['url' => 'Contact', 'bytes' => "\xFF", null]]);
		Assert::same(['paramsBase64' => ['RXhwaXJlcw==', 400, ['url' => 'Q29udGFjdA==', 'bytes' => '/w==', null]]], [$base64->getKey() => $base64->getValue()]);
		Assert::throws(function () use ($factory): void {
			$factory->create('params', ["\xFF", ["\xFF" => 'Contact']]);
		}, LogicException::class, 'A stored result cannot carry a key that is not UTF-8');
	}

}

new SecurityTxtJsonValueFactoryTest()->run();
