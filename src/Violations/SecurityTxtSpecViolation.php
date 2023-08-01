<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

abstract class SecurityTxtSpecViolation
{

	/**
	 * @param list<string> $seeAlsoSections
	 */
	public function __construct(
		private readonly string $message,
		private readonly ?string $since,
		private readonly ?string $correctValue,
		private readonly string $howToFix,
		private readonly ?string $specSection,
		private readonly array $seeAlsoSections = [],
	) {
	}


	public function getMessage(): string
	{
		return $this->message;
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
