<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use DateTimeImmutable;
use gnupg;
use Spaze\SecurityTxt\Exceptions\SecurityTxtSignatureExtensionNotLoadedWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtSignatureInvalidError;

class SecurityTxtSignature
{

	private gnupg $gnupg;


	/**
	 * @throws SecurityTxtSignatureExtensionNotLoadedWarning
	 */
	public function init(): void
	{
		if (!extension_loaded('gnupg')) {
			throw new SecurityTxtSignatureExtensionNotLoadedWarning();
		}
		$this->gnupg = new gnupg();
	}


	/**
	 * @throws SecurityTxtSignatureExtensionNotLoadedWarning
	 * @throws SecurityTxtSignatureInvalidError
	 */
	public function verify(string $contents): SecurityTxtSignatureVerifyResult
	{
		$this->init();
		$signature = $this->gnupg->verify($contents, false)[0];
		if (!$this->isSignatureKindaOkay($signature['summary'])) {
			throw new SecurityTxtSignatureInvalidError();
		}
		return new SecurityTxtSignatureVerifyResult($signature['fingerprint'], (new DateTimeImmutable())->setTimestamp($signature['timestamp']));
	}


	private function isSignatureKindaOkay(int $summary): bool
	{
		return ($summary & GNUPG_SIGSUM_GREEN || $summary & GNUPG_SIGSUM_KEY_MISSING) && !($summary & GNUPG_SIGSUM_RED);
	}


	public function isCleartextHeader(string $line): bool
	{
		return $line === '-----BEGIN PGP SIGNED MESSAGE-----';
	}

}
