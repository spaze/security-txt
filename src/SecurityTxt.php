<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Exceptions\SecurityTxtAcknowledgmentsNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtAcknowledgmentsNotUriSyntaxError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtCanonicalNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtCanonicalNotUriError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtContactNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtContactNotUriError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtEncryptionNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtEncryptionNotUriSyntaxError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiredError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtFieldNotUriError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtFieldUriNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtHiringNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtHiringNotUriSyntaxError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPolicyNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPolicyNotUriSyntaxError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesCommonMistakeError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesEmptyError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesWrongLanguageTagsError;
use Spaze\SecurityTxt\Fields\Acknowledgments;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\Fields\Contact;
use Spaze\SecurityTxt\Fields\Encryption;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\Hiring;
use Spaze\SecurityTxt\Fields\Policy;
use Spaze\SecurityTxt\Fields\PreferredLanguages;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;

class SecurityTxt
{

	private bool $allowFieldsWithInvalidValues = false;
	private ?Expires $expires = null;
	private ?SecurityTxtSignatureVerifyResult $signatureVerifyResult = null;
	private ?PreferredLanguages $preferredLanguages = null;

	/**
	 * @var list<Canonical>
	 */
	private array $canonical = [];

	/**
	 * @var list<Contact>
	 */
	private array $contact = [];

	/**
	 * @var list<Acknowledgments>
	 */
	private array $acknowledgments = [];

	/**
	 * @var list<Hiring>
	 */
	private array $hiring = [];

	/**
	 * @var list<Policy>
	 */
	private array $policy = [];

	/**
	 * @var list<Encryption>
	 */
	private array $encryption = [];


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
	 * @throws SecurityTxtCanonicalNotUriError|SecurityTxtFieldNotUriError
	 * @throws SecurityTxtCanonicalNotHttpsError|SecurityTxtFieldUriNotHttpsError
	 */
	public function addCanonical(Canonical $canonical): void
	{
		$this->setValue(
			function () use ($canonical): void {
				$this->canonical[] = $canonical;
			},
			function () use ($canonical): void {
				$this->checkUri($canonical->getUri(), SecurityTxtCanonicalNotUriError::class, SecurityTxtCanonicalNotHttpsError::class);
			},
		);
	}


	/**
	 * @return list<Canonical>
	 */
	public function getCanonical(): array
	{
		return $this->canonical;
	}


	/**
	 * @throws SecurityTxtContactNotUriError|SecurityTxtFieldNotUriError
	 * @throws SecurityTxtContactNotHttpsError|SecurityTxtFieldUriNotHttpsError
	 */
	public function addContact(Contact $contact): void
	{
		$this->setValue(
			function () use ($contact): void {
				$this->contact[] = $contact;
			},
			function () use ($contact): void {
				$this->checkUri($contact->getUri(), SecurityTxtContactNotUriError::class, SecurityTxtContactNotHttpsError::class);
			},
		);
	}


	/**
	 * @return list<Contact>
	 */
	public function getContact(): array
	{
		return $this->contact;
	}


	/**
	 * @throws SecurityTxtPreferredLanguagesEmptyError
	 * @throws SecurityTxtPreferredLanguagesWrongLanguageTagsError
	 * @throws SecurityTxtPreferredLanguagesCommonMistakeError
	 */
	public function setPreferredLanguages(PreferredLanguages $preferredLanguages): void
	{
		$this->setValue(
			function () use ($preferredLanguages): void {
				$this->preferredLanguages = $preferredLanguages;
			},
			function () use ($preferredLanguages): void {
				if (!$preferredLanguages->getLanguages()) {
					throw new SecurityTxtPreferredLanguagesEmptyError();
				}
				$wrongLanguages = [];
				foreach ($preferredLanguages->getLanguages() as $key => $value) {
					if (!preg_match('/^([a-z]{2,3}(-[a-z0-9]+)*|[xi]-[a-z0-9]+)$/i', $value)) {
						$wrongLanguages[$key + 1] = $value;
					}
				}
				if ($wrongLanguages) {
					throw new SecurityTxtPreferredLanguagesWrongLanguageTagsError($wrongLanguages);
				}
				foreach ($preferredLanguages->getLanguages() as $key => $value) {
					if (preg_match('/^cz-?/i', $value)) {
						throw new SecurityTxtPreferredLanguagesCommonMistakeError(
							$key + 1,
							$value,
							preg_replace('/^cz$|cz(-)/i', 'cs$1', $value),
							'the code for Czech language is `cs`, not `cz`',
						);
					}
				}
			},
		);
	}


	public function getPreferredLanguages(): ?PreferredLanguages
	{
		return $this->preferredLanguages;
	}


	/**
	 * @throws SecurityTxtAcknowledgmentsNotUriSyntaxError|SecurityTxtFieldNotUriError
	 * @throws SecurityTxtAcknowledgmentsNotHttpsError|SecurityTxtFieldUriNotHttpsError
	 */
	public function addAcknowledgments(Acknowledgments $acknowledgments): void
	{
		$this->setValue(
			function () use ($acknowledgments): void {
				$this->acknowledgments[] = $acknowledgments;
			},
			function () use ($acknowledgments): void {
				$this->checkUri($acknowledgments->getUri(), SecurityTxtAcknowledgmentsNotUriSyntaxError::class, SecurityTxtAcknowledgmentsNotHttpsError::class);
			},
		);
	}


	/**
	 * @return list<Acknowledgments>
	 */
	public function getAcknowledgments(): array
	{
		return $this->acknowledgments;
	}


	/**
	 * @throws SecurityTxtHiringNotUriSyntaxError|SecurityTxtFieldNotUriError
	 * @throws SecurityTxtHiringNotHttpsError|SecurityTxtFieldUriNotHttpsError
	 */
	public function addHiring(Hiring $hiring): void
	{
		$this->setValue(
			function () use ($hiring): void {
				$this->hiring[] = $hiring;
			},
			function () use ($hiring): void {
				$this->checkUri($hiring->getUri(), SecurityTxtHiringNotUriSyntaxError::class, SecurityTxtHiringNotHttpsError::class);
			},
		);
	}


	/**
	 * @return list<Hiring>
	 */
	public function getHiring(): array
	{
		return $this->hiring;
	}


	/**
	 * @throws SecurityTxtPolicyNotUriSyntaxError|SecurityTxtFieldNotUriError
	 * @throws SecurityTxtPolicyNotHttpsError|SecurityTxtFieldUriNotHttpsError
	 */
	public function addPolicy(Policy $policy): void
	{
		$this->setValue(
			function () use ($policy): void {
				$this->policy[] = $policy;
			},
			function () use ($policy): void {
				$this->checkUri($policy->getUri(), SecurityTxtPolicyNotUriSyntaxError::class, SecurityTxtPolicyNotHttpsError::class);
			},
		);
	}


	/**
	 * @return list<Policy>
	 */
	public function getPolicy(): array
	{
		return $this->policy;
	}


	/**
	 * @throws SecurityTxtEncryptionNotUriSyntaxError|SecurityTxtFieldNotUriError
	 * @throws SecurityTxtEncryptionNotHttpsError|SecurityTxtFieldUriNotHttpsError
	 */
	public function addEncryption(Encryption $encryption): void
	{
		$this->setValue(
			function () use ($encryption): void {
				$this->encryption[] = $encryption;
			},
			function () use ($encryption): void {
				$this->checkUri($encryption->getUri(), SecurityTxtEncryptionNotUriSyntaxError::class, SecurityTxtEncryptionNotHttpsError::class);
			},
		);
	}


	/**
	 * @return list<Encryption>
	 */
	public function getEncryption(): array
	{
		return $this->encryption;
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


	/**
	 * @template TNotUri of SecurityTxtFieldNotUriError
	 * @template TNotHttps of SecurityTxtFieldUriNotHttpsError
	 * @param class-string<TNotUri> $notUriError
	 * @param class-string<TNotHttps> $notHttpsError
	 * @throws TNotUri
	 * @throws TNotHttps
	 */
	private function checkUri(string $uri, string $notUriError, string $notHttpsError): void
	{
		$scheme = parse_url($uri, PHP_URL_SCHEME);
		if (!$scheme) {
			throw new $notUriError($uri);
		}
		if (strtolower($scheme) === 'http') {
			throw new $notHttpsError($uri);
		}
	}

}
