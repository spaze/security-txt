<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Exceptions\SecurityTxtCanonicalNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiredError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;

class SecurityTxt
{

	private bool $allowFieldsWithInvalidValues = false;
	private ?Expires $expires = null;
	private ?SecurityTxtSignatureVerifyResult $signatureVerifyResult = null;

	/**
	 * @var array<int, Canonical>
	 */
	private array $canonical = [];


	public function allowFieldsWithInvalidValues(): void
	{
		$this->allowFieldsWithInvalidValues = true;
	}


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


	public function setSignatureVerifyResult(SecurityTxtSignatureVerifyResult $signatureVerifyResult): void
	{
		$this->signatureVerifyResult = $signatureVerifyResult;
	}


	public function getSignatureVerifyResult(): ?SecurityTxtSignatureVerifyResult
	{
		return $this->signatureVerifyResult;
	}


	/**
	 * @throws SecurityTxtCanonicalNotHttpsError
	 */
	public function addCanonical(Canonical $canonical): void
	{
		$this->setValue(
			function () use ($canonical): void {
				$this->canonical[] = $canonical;
			},
			function () use ($canonical): void {
				$scheme = parse_url($canonical->getUri(), PHP_URL_SCHEME);
				if ($scheme && strtolower($scheme) === 'http') {
					throw new SecurityTxtCanonicalNotHttpsError();
				}
			},
		);
	}


	/**
	 * @return array<int, Canonical>
	 */
	public function getCanonical(): array
	{
		return $this->canonical;
	}


	/**
	 * @param callable(): void $setValue
	 * @param callable(): void $validator
	 * @return void
	 */
	private function setValue(callable $setValue, callable $validator): void
	{
		if ($this->allowFieldsWithInvalidValues) {
			$setValue();
			$validator();
		} else {
			$validator();
			$setValue();
		}
	}

}
