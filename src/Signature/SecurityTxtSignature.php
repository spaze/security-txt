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


	public function __construct(
		private readonly ?string $homeDir = null,
	) {
	}


	/**
	 * @throws SecurityTxtSignatureExtensionNotLoadedWarning
	 */
	public function init(): void
	{
		if (!extension_loaded('gnupg')) {
			throw new SecurityTxtSignatureExtensionNotLoadedWarning();
		}
		$options = ['home_dir' => $this->homeDir];
		$this->gnupg = new gnupg(array_filter($options));
	}


	/**
	 * @throws SecurityTxtSignatureExtensionNotLoadedWarning
	 * @throws SecurityTxtSignatureInvalidError
	 */
	public function verify(string $contents): SecurityTxtSignatureVerifyResult
	{
		$this->init();
		$signatures = $this->gnupg->verify($contents, false);
		if (!$signatures || !isset($signatures[0])) {
			throw new SecurityTxtSignatureInvalidError();
		}
		$signature = $signatures[0];
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
