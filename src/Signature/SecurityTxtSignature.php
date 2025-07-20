<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use DateTimeImmutable;
use gnupg;
use SensitiveParameter;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotCreateSignatureException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotVerifySignatureException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtSigningKeyBadPassphraseException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtSigningKeyNoPassphraseSetException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtUnknownSigningKeyException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtUnusableSigningKeyException;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureProvider;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureInvalid;

final class SecurityTxtSignature
{

	private const int GPG_ERROR_GPG_AGENT_BAD_PASSPHRASE = 67108875;
	private const int GPG_ERROR_GPGME_END_OF_FILE = 117456895;
	private const string GPG_MESSAGE_NO_PASSPHRASE_SET = 'no passphrase set';

	/** @var array<string, true> */
	private array $addedSignKeys = [];


	public function __construct(
		private readonly SecurityTxtSignatureProvider $signatureProvider,
		private readonly ?string $homeDir = null,
	) {
	}


	/**
	 * @throws SecurityTxtError
	 * @throws SecurityTxtWarning
	 * @throws SecurityTxtCannotVerifySignatureException
	 */
	public function verify(string $contents): SecurityTxtSignatureVerifyResult
	{
		if (!extension_loaded('gnupg')) {
			throw new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded());
		}
		$options = $this->homeDir !== null ? ['home_dir' => $this->homeDir] : [];
		$signatures = new gnupg($options)->verify($contents, false);
		if ($signatures === false || !isset($signatures[0])) {
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
		return (($summary & GNUPG_SIGSUM_GREEN) !== 0 || ($summary & GNUPG_SIGSUM_KEY_MISSING) !== 0) && ($summary & GNUPG_SIGSUM_RED) === 0;
	}


	public function isCleartextHeader(string $line): bool
	{
		return $line === '-----BEGIN PGP SIGNED MESSAGE-----';
	}


	/**
	 * Sign the contents with OpenPGP/GnuPG, use only if you know what you're doing.
	 *
	 * Another option is to use the gpg command line utility, as using the sign() method requires
	 * access to your keyring with the signing key, which means your app can also access it,
	 * which means a security problem in your app can leak the signing key. You want to avoid that.
	 *
	 * @param string $keyFingerprint Can be anything that refers to a unique key (user id, key id, fingerprint, ...)
	 * @throws SecurityTxtCannotCreateSignatureException
	 * @throws SecurityTxtSigningKeyBadPassphraseException
	 * @throws SecurityTxtSigningKeyNoPassphraseSetException
	 * @throws SecurityTxtUnknownSigningKeyException
	 * @throws SecurityTxtUnusableSigningKeyException
	 */
	public function sign(
		string $text,
		string $keyFingerprint,
		#[SensitiveParameter] ?string $keyPassphrase = null,
	): string {
		$this->addSignKey($keyFingerprint, $keyPassphrase);
		$signed = $this->signatureProvider->sign($text);
		if ($signed === false) {
			throw new SecurityTxtCannotCreateSignatureException($keyFingerprint, $this->signatureProvider->getErrorInfo());
		}
		return $signed;
	}


	/**
	 * @throws SecurityTxtSigningKeyBadPassphraseException
	 * @throws SecurityTxtSigningKeyNoPassphraseSetException
	 * @throws SecurityTxtUnknownSigningKeyException
	 * @throws SecurityTxtUnusableSigningKeyException
	 */
	private function addSignKey(string $keyFingerprint, #[SensitiveParameter] ?string $keyPassphrase): void
	{
		if (isset($this->addedSignKeys[$keyFingerprint])) {
			return;
		}
		if (!$this->signatureProvider->addSignKey($keyFingerprint, $keyPassphrase ?? '')) {
			$error = $this->signatureProvider->getErrorInfo();
			if ($error->getCode() === 1 && $error->getMessage() === self::GPG_MESSAGE_NO_PASSPHRASE_SET) {
				throw new SecurityTxtSigningKeyNoPassphraseSetException($keyFingerprint);
			} elseif ($error->getCode() === self::GPG_ERROR_GPG_AGENT_BAD_PASSPHRASE) {
				throw new SecurityTxtSigningKeyBadPassphraseException($keyFingerprint);
			} elseif ($error->getCode() === self::GPG_ERROR_GPGME_END_OF_FILE) {
				throw new SecurityTxtUnknownSigningKeyException($keyFingerprint);
			}
			throw new SecurityTxtUnusableSigningKeyException($keyFingerprint, $error);
		}
		$this->addedSignKeys[$keyFingerprint] = true;
	}

}
