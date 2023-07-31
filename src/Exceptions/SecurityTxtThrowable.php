<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Exception;
use Throwable;

abstract class SecurityTxtThrowable extends Exception
{

	/**
	 * @param list<string> $seeAlsoSections
	 */
	public function __construct(
		string $message,
		private readonly ?string $since,
		private readonly ?string $correctValue,
		private readonly string $howToFix,
		private readonly ?string $specSection,
		private readonly array $seeAlsoSections = [],
		?Throwable $previous = null,
	) {
		parent::__construct($message, previous: $previous);
	}


	public function getSince(): ?string
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
	 * @return list<string>
	 */
	public function getSeeAlsoSections(): array
	{
		return $this->seeAlsoSections;
	}

}
