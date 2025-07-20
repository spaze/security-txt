<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Providers;

use gnupg;
use Override;
use SensitiveParameter;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotCreateSignatureExtensionNotLoadedException;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureErrorInfo;

final class SecurityTxtSignatureGnuPgProvider implements SecurityTxtSignatureProvider
{

	private ?gnupg $gnupg = null;


	public function __construct(private readonly ?string $homeDir = null)
	{
	}


	/**
	 * @throws SecurityTxtCannotCreateSignatureExtensionNotLoadedException
	 */
	#[Override]
	public function addSignKey(string $fingerprint, #[SensitiveParameter] string $passphrase = ''): bool
	{
		return $this->getGnuPg()->addsignkey($fingerprint, $passphrase);
	}


	/**
	 * @throws SecurityTxtCannotCreateSignatureExtensionNotLoadedException
	 */
	#[Override]
	public function getErrorInfo(): SecurityTxtSignatureErrorInfo
	{
		$error = $this->getGnuPg()->geterrorinfo();
		return new SecurityTxtSignatureErrorInfo(
			is_string($error['generic_message']) || $error['generic_message'] === false ? $error['generic_message'] : '<unknown>',
			is_int($error['gpgme_code']) ? $error['gpgme_code'] : -1,
			is_string($error['gpgme_source']) ? $error['gpgme_source'] : '<unknown>',
			is_string($error['gpgme_message']) ? $error['gpgme_message'] : '<unknown>',
		);
	}


	/**
	 * @throws SecurityTxtCannotCreateSignatureExtensionNotLoadedException
	 */
	#[Override]
	public function sign(string $text): false|string
	{
		return $this->getGnuPg()->sign($text);
	}


	/**
	 * @throws SecurityTxtCannotCreateSignatureExtensionNotLoadedException
	 */
	private function getGnuPg(): gnupg
	{
		if (!extension_loaded('gnupg')) {
			throw new SecurityTxtCannotCreateSignatureExtensionNotLoadedException();
		}
		if ($this->gnupg === null) {
			$options = $this->homeDir !== null ? ['home_dir' => $this->homeDir] : [];
			$this->gnupg = new gnupg($options);
		}
		return $this->gnupg;
	}

}
