<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

class PreferredLanguages
{

	/**
	 * @param list<string> $languages
	 */
	public function __construct(
		private readonly array $languages,
	) {
	}


	/**
	 * @return list<string>
	 */
	public function getLanguages(): array
	{
		return $this->languages;
	}

}
