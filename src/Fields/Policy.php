<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

class Policy
{

	public function __construct(
		private readonly string $uri,
	) {
	}


	public function getUri(): string
	{
		return $this->uri;
	}

}
