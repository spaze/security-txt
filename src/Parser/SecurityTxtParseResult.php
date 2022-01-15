<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\SecurityTxt;

class SecurityTxtParseResult
{

	/**
	 * @param SecurityTxt $securityTxt
	 * @param array<int, array<int, SecurityTxtError>> $parseErrors
	 * @param array<int, SecurityTxtError> $fileErrors
	 * @param array<int, array<int, SecurityTxtWarning>> $parseWarnings
	 */
	public function __construct(
		private SecurityTxt $securityTxt,
		private array $parseErrors,
		private array $fileErrors,
		private array $parseWarnings,
	) {
	}


	public function getSecurityTxt(): SecurityTxt
	{
		return $this->securityTxt;
	}


	/**
	 * @return array<int, array<int, SecurityTxtError>>
	 */
	public function getParseErrors(): array
	{
		return $this->parseErrors;
	}


	/**
	 * @return array<int, SecurityTxtError>
	 */
	public function getFileErrors(): array
	{
		return $this->fileErrors;
	}


	/**
	 * @return array<int, array<int, SecurityTxtWarning>>
	 */
	public function getParseWarnings(): array
	{
		return $this->parseWarnings;
	}

}
