<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiredError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Fields\Expires;

class SecurityTxt
{

	private ?Expires $expires = null;


	/**
	 * @throws SecurityTxtExpiredError
	 * @throws SecurityTxtExpiresTooLongWarning
	 */
	public function setExpires(Expires $expires): void
	{
		$this->expires = $expires;
		if ($expires->isExpired()) {
			throw new SecurityTxtExpiredError();
		}
		if ($expires->inDays() > 366) {
			throw new SecurityTxtExpiresTooLongWarning();
		}
	}


	public function getExpires(): ?Expires
	{
		return $this->expires;
	}

}
