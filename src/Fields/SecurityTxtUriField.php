<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use JsonSerializable;

abstract class SecurityTxtUriField implements JsonSerializable
{

	public function __construct(
		private readonly string $uri,
	) {
	}


	public function getUri(): string
	{
		return $this->uri;
	}


	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'uri' => $this->getUri(),
		];
	}

}
