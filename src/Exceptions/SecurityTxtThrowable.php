<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Exception;
use Throwable;

abstract class SecurityTxtThrowable extends Exception
{

	/**
	 * @param string $message
	 * @param string $since
	 * @param string|null $correctValue
	 * @param string $howToFix
	 * @param string|null $specSection
	 * @param array<int, string> $seeAlsoSections
	 * @param Throwable|null $previous
	 */
	public function __construct(
		string $message,
		private string $since,
		private ?string $correctValue,
		private string $howToFix,
		private ?string $specSection,
		private array $seeAlsoSections = [],
		?Throwable $previous = null,
	) {
		parent::__construct($message, previous: $previous);
	}


	public function getSince(): string
	{
		return $this->since;
	}


	public function getCorrectValue(): ?string
	{
		return $this->correctValue;
	}


	public function getHowToFix(): string
	{
		return $this->howToFix;
	}


	public function getSpecSection(): ?string
	{
		return $this->specSection;
	}


	/**
	 * @return array<int, string>
	 */
	public function getSeeAlsoSections(): array
	{
		return $this->seeAlsoSections;
	}

}
