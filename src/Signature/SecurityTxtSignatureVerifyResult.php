<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use DateTimeImmutable;

class SecurityTxtSignatureVerifyResult
{

	public function __construct(
		private readonly string $keyFingerprint,
		private readonly DateTimeImmutable $date,
	) {
	}


	public function getKeyFingerprint(): string
	{
		return $this->keyFingerprint;
	}


	public function getDate(): DateTimeImmutable
	{
		return $this->date;
	}

}
