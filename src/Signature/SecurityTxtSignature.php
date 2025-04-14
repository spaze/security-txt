<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use DateTimeImmutable;
use gnupg;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotVerifySignatureException;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureInvalid;

final class SecurityTxtSignature
{

	private gnupg $gnupg;


	public function __construct(
		private readonly ?string $homeDir = null,
	) {
	}


	/**
	 * @throws SecurityTxtWarning
	 */
	public function init(): void
	{
		if (!extension_loaded('gnupg')) {
			throw new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded());
		}
		$options = ['home_dir' => $this->homeDir];
		$this->gnupg = new gnupg(array_filter($options));
	}


	/**
	 * @throws SecurityTxtError
	 * @throws SecurityTxtWarning
	 * @throws SecurityTxtCannotVerifySignatureException
	 */
	public function verify(string $contents): SecurityTxtSignatureVerifyResult
	{
		$this->init();
		$signatures = $this->gnupg->verify($contents, false);
		if (!$signatures || !isset($signatures[0])) {
			throw new SecurityTxtError(new SecurityTxtSignatureInvalid());
		}
		$signature = $signatures[0];
		if (!is_array($signature)) {
			throw new SecurityTxtCannotVerifySignatureException('signature is not an array');
		}
		if (!isset($signature['summary']) || !is_int($signature['summary'])) {
			throw new SecurityTxtCannotVerifySignatureException('summary is missing or not a string');
		}
		if (!$this->isSignatureKindaOkay($signature['summary'])) {
			throw new SecurityTxtError(new SecurityTxtSignatureInvalid());
		}
		if (!isset($signature['fingerprint']) || !is_string($signature['fingerprint'])) {
			throw new SecurityTxtCannotVerifySignatureException('fingerprint is missing or not a string');
		}
		if (!isset($signature['timestamp']) || !is_int($signature['timestamp'])) {
			throw new SecurityTxtCannotVerifySignatureException('timestamp is missing or not a string');
		}
		return new SecurityTxtSignatureVerifyResult($signature['fingerprint'], new DateTimeImmutable()->setTimestamp($signature['timestamp']));
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
