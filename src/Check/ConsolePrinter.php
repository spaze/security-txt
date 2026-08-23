<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

/**
 * @internal Should be used only in the check host class
 */
final class ConsolePrinter
{

	private bool $colors = false;


	public function enableColors(): void
	{
		$this->colors = true;
	}


	public function info(string $message): void
	{
		$this->print($this->colorDarkGray('[Info]'), $message);
	}


	public function error(string $message): void
	{
		$this->print($this->colorRed('[Error]'), $message);
	}


	public function warning(string $message): void
	{
		$this->print($this->colorBold('[Warning]'), $message);
	}


	private function print(string $level, string $message): void
	{
		$message = $this->removeControlCharacters($message);
		$message = str_replace("\n", "\n{$level} ", $message);
		echo "{$level} {$message}\n";
	}


	/**
	 * Messages quote strings the checked host controls, a `Location` header or a field value read from its `security.txt`, and those arrive with their bytes intact. Left
	 * alone, a host decides what the output says: it can erase a line already printed, move the cursor over one, reverse what follows with a bidirectional override, or hide
	 * part of a name behind an invisible character, and the output is the whole point of a tool that reports on hosts it does not trust.
	 * What is kept is listed rather than what is removed, so that anything left off the list is a character that does not print rather than a hole: printable ASCII, the
	 * newline the caller indents after, the arrow this library prints between redirects, and, only when colors are on, the five sequences it adds itself.
	 * Those five cannot be told apart from a host's own, because a caller colors parts of a message before passing it in, so with colors on a host can color its own text and
	 * do nothing else with them; with colors off nothing escapes at all. Telling the two apart needs the printer to take a format and its values separately, which is an API
	 * change and does not belong on a branch that takes security fixes only.
	 */
	private function removeControlCharacters(string $message): string
	{
		$keep = $this->colors ? '\x1b\[(?:0|1|1;31|1;32|1;90)m|' : '';
		$cleaned = preg_replace('~(?:' . $keep . '\xe2\x86\x92)(*SKIP)(*FAIL)|[^\x20-\x7e\n]~', '', $message);
		return $cleaned ?? '';
	}


	public function colorRed(string $message): string
	{
		return $this->color("\033[1;31m", $message);
	}


	public function colorGreen(string $message): string
	{
		return $this->color("\033[1;32m", $message);
	}


	public function colorDarkGray(string $message): string
	{
		return $this->color("\033[1;90m", $message);
	}


	public function colorBold(string $message): string
	{
		return $this->color("\033[1m", $message);
	}


	private function color(string $color, string $message): string
	{
		return sprintf('%s%s%s', $this->colors ? $color : '', $message, $this->colors ? "\033[0m" : '');
	}

}
