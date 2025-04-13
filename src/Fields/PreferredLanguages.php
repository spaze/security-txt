<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use JsonSerializable;

readonly class PreferredLanguages implements JsonSerializable
{

	/**
	 * @param list<string> $languages
	 */
	public function __construct(
		private array $languages,
	) {
	}


	/**
	 * @return list<string>
	 */
	public function getLanguages(): array
	{
		return $this->languages;
	}


	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'languages' => $this->getLanguages(),
		];
	}

}
