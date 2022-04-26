<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtTopLevelDiffersWarning extends SecurityTxtWarning
{

	public function __construct(
		private readonly string $wellKnownContents,
		private readonly string $topLevelContents,
		?Throwable $previous = null,
	) {
		parent::__construct(
			'The file at the top-level path is different than the one in the `/.well-known/` path',
			'draft-foudil-securitytxt-09',
			null,
			'Redirect the top-level file to the one under the `/.well-known/` path',
			'4',
			previous: $previous,
		);
	}


	public function getWellKnownContents(): string
	{
		return $this->wellKnownContents;
	}


	public function getTopLevelContents(): string
	{
		return $this->topLevelContents;
	}

}
