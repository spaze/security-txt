<?php
/** @noinspection HttpUrlsUsage */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class ConsolePrinterTest extends TestCase
{

	public function testPrinterColorsOn(): void
	{
		$printer = new ConsolePrinter();
		$printer->setColors(true);
		ob_start();
		$printer->ok('🕺');
		$printer->info('Never');
		$printer->error('gonna');
		$printer->warning('give');
		$printer->info('<green>you</green>');
		$printer->info('<b>up</b>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;32m[OK][0m 🕺
		[1;90m[Info][0m Never
		[1;31m[Error][0m gonna
		[1m[Warning][0m give
		[1;90m[Info][0m [1;32myou[0m
		[1;90m[Info][0m [1mup[0m
		EOT;
		Assert::same($expected . "\n", $output);
	}


	public function testPrinterColorsOff(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		$printer->ok('🕺');
		$printer->info('Never');
		$printer->error('gonna');
		$printer->warning('give');
		$printer->info('<green>you</green>');
		$printer->info('<b>up</b>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[OK] 🕺
		[Info] Never
		[Error] gonna
		[Warning] give
		[Info] you
		[Info] up
		EOT;
		Assert::same($expected . "\n", $output);
	}


	public function testPrinterEncodesControlCharactersInValues(): void
	{
		$printer = new ConsolePrinter();
		$printer->setColors(true);
		ob_start();
		$printer->info('Redirected to <b>%s</b>', "https://evil.example/\x1b]0;pwned\x07x");
		$printer->error('%s', "Erase\x1b[2K and \rrewrite\x7f");
		$output = ob_get_clean();
		$expected = "\x1b[1;90m[Info]\x1b[0m Redirected to \x1b[1mhttps://evil.example/%1B]0;pwned%07x\x1b[0m\n"
			. "\x1b[1;31m[Error]\x1b[0m Erase%1B[2K and %0Drewrite%7F\n";
		Assert::same($expected, $output);
	}


	public function testPrinterDoesNotLetValuesSetColors(): void
	{
		$printer = new ConsolePrinter();
		$printer->setColors(true);
		ob_start();
		// Neither as an escape sequence nor as the markup a format would use, a value is never read as markup
		$printer->info('Redirected to %s', "https://evil.example/\x1b[1;32m[OK] The file is valid\x1b[0m");
		$printer->info('Redirected to %s', 'https://evil.example/<green>[OK] The file is valid</green>');
		$output = ob_get_clean();
		$expected = "\x1b[1;90m[Info]\x1b[0m Redirected to https://evil.example/%1B[1;32m[OK] The file is valid%1B[0m\n"
			. "\x1b[1;90m[Info]\x1b[0m Redirected to https://evil.example/<green>[OK] The file is valid</green>\n";
		Assert::same($expected, $output);
	}


	public function testPrinterEncodesC1AndBidiInValues(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		// U+009B is CSI for terminals that read C1, here erase line and switch to green
		$printer->info('Redirected to %s', "https://evil.example/\u{9B}2K\u{9B}1;32m[OK] The file is valid");
		// U+202E displays what follows right to left, no terminal cooperation needed
		$printer->info('Redirected to %s', "https://evil.example/\u{202E}dilav si elif ehT");
		$output = ob_get_clean();
		$expected = "[Info] Redirected to https://evil.example/%C2%9B2K%C2%9B1;32m[OK] The file is valid\n"
			. "[Info] Redirected to https://evil.example/%E2%80%AEdilav si elif ehT\n";
		Assert::same($expected, $output);
	}


	public function testPrinterKeepsPrintableAsciiInValuesAndEncodesTheRest(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		// A bare byte, the same control as UTF-8, a bidi override, a bidi mark, a line separator, a newline, delete, and a byte that is not UTF-8 at all
		$printer->info('%s', "a\x9bb\u{9B}c\u{202E}d\u{200E}e\u{2028}f\ng\x7fh\xffi");
		// Text a value has no business needing, this is a URL or a field value read from a security.txt, not prose
		$printer->info('%s', 'a © b → c 🕺 d é');
		$output = ob_get_clean();
		$expected = "[Info] a%9Bb%C2%9Bc%E2%80%AEd%E2%80%8Ee%E2%80%A8f%0Ag%7Fh%FFi\n"
			. "[Info] a %C2%A9 b %E2%86%92 c %F0%9F%95%BA d %C3%A9\n";
		Assert::same($expected, $output);
	}


	public function testPrinterKeepsAnythingInTheFormat(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		// The format is written in this codebase, it is where what this tool prints for itself belongs
		$printer->info('Redirected from %s → %s 🕺', 'a', 'b');
		$output = ob_get_clean();
		Assert::same("[Info] Redirected from a → b 🕺\n", $output);
	}


	public function testPrinterLeavesNothingButPrintableAsciiInAValue(): void
	{
		$printer = new ConsolePrinter();
		$value = '';
		for ($byte = 0; $byte <= 255; $byte++) {
			$value .= chr($byte);
		}
		ob_start();
		$printer->info('%s', $value);
		$output = ob_get_clean();
		// Every byte there is, not the handful anyone thought to list
		Assert::match('#^\\[Info\\] [\\x20-\\x7e]+$#', rtrim((string)$output, "\n"));
	}


	public function testPrinterReadsPercentTheSameWithAndWithoutValues(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		$printer->info('100%% done');
		$printer->info('100%% done, %s', 'really');
		$output = ob_get_clean();
		Assert::same("[Info] 100% done\n[Info] 100% done, really\n", $output);
	}


	public function testPrinterKeepsNewlinesInTheFormatOnly(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		// How many lines a message takes is the format's decision
		$printer->error("first\nsecond");
		// A value quoted in it does not get to add lines, not even ones with the level in front of them
		$printer->error('%s', "third\nfourth");
		$output = ob_get_clean();
		Assert::same("[Error] first\n[Error] second\n[Error] third%0Afourth\n", $output);
	}


	public function testPrinterDoesNotReadPercentInValues(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		$printer->info('Using %s', 'https://example.com/%s%d');
		$output = ob_get_clean();
		Assert::same("[Info] Using https://example.com/%s%d\n", $output);
	}

}

(new ConsolePrinterTest())->run();
