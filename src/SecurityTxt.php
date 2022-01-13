<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiredError;
use Spaze\SecurityTxt\Fields\Expires;

class SecurityTxt
{

	private ?Expires $expires = null;


	/**
	 * @throws SecurityTxtExpiredError
	 */
	public function setExpires(Expires $expires): void
	{
		$this->expires = $expires;
		if ($expires->isExpired()) {
			throw new SecurityTxtExpiredError();
		}
	}


	public function getExpires(): ?Expires
	{
		return $this->expires;
	}

}
