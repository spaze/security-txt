<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use JsonSerializable;
use Override;
use ValueError;

abstract class SecurityTxtSpecViolation implements JsonSerializable
{

	private readonly string $message;

	private readonly string $howToFix;


	/**
	 * @param list<mixed> $constructorParams
	 * @param literal-string $messageFormat Never build this from a field value or anything else read from the file, only the values are encoded when the message is printed. The analysers check this where the violation is constructed in code, they cannot check `SecurityTxtJson`, which replays whatever the serialized params hold
	 * @param list<string> $messageValues
	 * @param literal-string $howToFixFormat Never build this from a field value or anything else read from the file, only the values are encoded when the message is printed
	 * @param list<string> $howToFixValues
	 * @param list<string> $seeAlsoSections
	 * @throws ValueError
	 */
	public function __construct(
		private readonly array $constructorParams,
		private readonly string $messageFormat,
		private readonly array $messageValues,
		private readonly ?string $since,
		private readonly ?string $correctValue,
		private readonly string $howToFixFormat,
		private readonly array $howToFixValues,
		private readonly ?string $specSection,
		private readonly array $seeAlsoSections = [],
		private readonly ?string $specUrl = null,
	) {
		// Rendered here and not in the getter so that a format and values that disagree fail where `SecurityTxtJson` guards a replay of serialized params
		$this->message = vsprintf($this->messageFormat, $this->messageValues);
		$this->howToFix = vsprintf($this->howToFixFormat, $this->howToFixValues);
	}


	public function getMessage(): string
	{
		return $this->message;
	}


	/**
	 * `$piece` repeated once per item, separated by `$separator`, empty when there are none.
	 *
	 * @param literal-string $piece
	 * @param literal-string $separator
	 * @return literal-string
	 */
	protected function getRepeatedFormat(string $piece, int $count, string $separator = ', '): string
	{
		$format = '';
		for ($i = 0; $i < $count; $i++) {
			$format .= $format === '' ? $piece : $separator . $piece;
		}
		return $format;
	}


	/**
	 * @return literal-string
	 */
	public function getMessageFormat(): string
	{
		return $this->messageFormat;
	}


	/**
	 * @return list<string>
	 */
	public function getMessageValues(): array
	{
		return $this->messageValues;
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


	/**
	 * @return literal-string
	 */
	public function getHowToFixFormat(): string
	{
		return $this->howToFixFormat;
	}


	/**
	 * @return list<string>
	 */
	public function getHowToFixValues(): array
	{
		return $this->howToFixValues;
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


	public function getSpecUrl(): ?string
	{
		return $this->specUrl;
	}


	/**
	 * @return array<string, mixed>
	 */
	#[Override]
	public function jsonSerialize(): array
	{
		return [
			'class' => $this::class,
			'params' => $this->constructorParams,
			'message' => $this->getMessage(),
			'messageFormat' => $this->getMessageFormat(),
			'messageValues' => $this->getMessageValues(),
			'since' => $this->getSince(),
			'correctValue' => $this->getCorrectValue(),
			'howToFix' => $this->getHowToFix(),
			'howToFixFormat' => $this->getHowToFixFormat(),
			'howToFixValues' => $this->getHowToFixValues(),
			'specSection' => $this->getSpecSection(),
			'seeAlsoSections' => $this->getSeeAlsoSections(),
			'specUrl' => $this->getSpecUrl(),
		];
	}

}
