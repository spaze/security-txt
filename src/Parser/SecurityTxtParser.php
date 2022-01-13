<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Parser\LineProcessors\ExpiresCheckMultipleFields;
use Spaze\SecurityTxt\Parser\LineProcessors\ExpiresSetFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\LineProcessor;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;

class SecurityTxtParser
{

	/** @var array<int, string> */
	private array $lines = [];

	/**
	 * @var array<string, array<int, LineProcessor>>
	 */
	private array $lineProcessors = [];

	/** @var array<int, array<int, SecurityTxtError>> */
	private array $parseErrors = [];


	public function __construct(
		private SecurityTxtValidator $validator,
	) {
		$this->lineProcessors[SecurityTxtField::Expires->value] = [
			new ExpiresCheckMultipleFields(),
			new ExpiresSetFieldValue(),
		];
	}


	private function processLine(int $lineNumber, string $value, SecurityTxtField $field, SecurityTxt $securityTxt): void
	{
		foreach ($this->lineProcessors[$field->value] as $processor) {
			try {
				$processor->process($value, $securityTxt);
			} catch (SecurityTxtError $e) {
				$this->parseErrors[$lineNumber][] = $e;
			}
		}
	}


	public function parseString(string $contents): SecurityTxtParseResult
	{
		$this->parseErrors = [];
		$lines = explode("\n", $contents);
		$this->lines = array_map(function (string $line): string {
			return trim($line);
		}, $lines);
		$securityTxt = new SecurityTxt();
		for ($lineNumber = 1; $lineNumber <= count($this->lines); $lineNumber++) {
			$line = $this->lines[$lineNumber - 1];
			if (str_starts_with($line, '#')) {
				continue;
			}
			$field = explode(':', $line, 2);
			if (count($field) !== 2) {
				continue;
			}
			$fieldName = strtolower($field[0]);
			$fieldValue = trim($field[1]);
			if ($fieldName === strtolower(SecurityTxtField::Expires->value)) {
				$this->processLine($lineNumber, $fieldValue, SecurityTxtField::Expires, $securityTxt);
			}
		}
		$validateResult = $this->validator->validate($securityTxt);
		return new SecurityTxtParseResult($securityTxt, $this->parseErrors, $validateResult->getErrors());
	}


	public function getLine(int $lineNumber): ?string
	{
		return $this->lines[$lineNumber] ?? null;
	}

}
