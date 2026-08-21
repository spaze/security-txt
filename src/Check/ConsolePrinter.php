<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

/**
 * Prints messages built from a format and values.
 *
 * The format is written in this codebase and is the only part that can ask for colors, and the only part that may be anything other than printable ASCII. The values come
 * from the checked host, a `Location` header or a field value read from its `security.txt` for example, and are encoded, never read as markup. Colors are resolved in the
 * format before the values are put in it, so a value can neither color itself nor reach the terminal as an escape sequence.
 *
 * @internal Should be used only in the check host class
 */
final class ConsolePrinter
{

	private const array COLORS = [
		'<b>' => "\033[1m",
		'<red>' => "\033[1;31m",
		'<green>' => "\033[1;32m",
		'<gray>' => "\033[1;90m",
		'</b>' => "\033[0m",
		'</red>' => "\033[0m",
		'</green>' => "\033[0m",
		'</gray>' => "\033[0m",
	];

	private bool $colors = false;


	public function setColors(bool $colors): void
	{
		$this->colors = $colors;
	}


	/**
	 * @param literal-string $format
	 */
	public function ok(string $format, string ...$values): void
	{
		$this->print('<green>[OK]</green>', $format, $values);
	}


	/**
	 * @param literal-string $format
	 */
	public function info(string $format, string ...$values): void
	{
		$this->print('<gray>[Info]</gray>', $format, $values);
	}


	/**
	 * @param literal-string $format
	 */
	public function error(string $format, string ...$values): void
	{
		$this->print('<red>[Error]</red>', $format, $values);
	}


	/**
	 * @param literal-string $format
	 */
	public function warning(string $format, string ...$values): void
	{
		$this->print('<b>[Warning]</b>', $format, $values);
	}


	/**
	 * @param literal-string $format
	 * @param array<array-key, string> $values Used in the order they came in, `vsprintf()` does not read the keys
	 */
	private function print(string $level, string $format, array $values): void
	{
		$level = $this->addColors($level);
		$message = vsprintf($this->addColors($format), array_map($this->encodeNonPrintable(...), $values));
		$message = str_replace("\n", "\n{$level} ", $message);
		echo "{$level} {$message}\n";
	}


	private function addColors(string $format): string
	{
		$replacements = $this->colors ? array_values(self::COLORS) : array_fill(0, count(self::COLORS), '');
		return str_replace(array_keys(self::COLORS), $replacements, $format);
	}


	/**
	 * A value is a URL, a host, an IP address or a field value read from a `security.txt`, none of which needs more than printable ASCII to be understood, while one control
	 * character or bidirectional override in one changes what the whole line says. Bytes rather than code points, so a value that is not valid UTF-8 is encoded as well, and
	 * `rawurlencode()` is the notation `Uri\WhatWg\Url` uses for the same bytes.
	 */
	private function encodeNonPrintable(string $value): string
	{
		$encoded = preg_replace_callback(
			'/[^\x20-\x7e]/',
			function (array $matches): string {
				return rawurlencode($matches[0]);
			},
			$value,
		);
		// Fails closed, printing nothing beats printing what this method exists to encode
		return $encoded ?? '';
	}

}
