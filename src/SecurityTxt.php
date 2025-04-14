<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use JsonSerializable;
use Override;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fields\Acknowledgments;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\Fields\Contact;
use Spaze\SecurityTxt\Fields\Encryption;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\Hiring;
use Spaze\SecurityTxt\Fields\Policy;
use Spaze\SecurityTxt\Fields\PreferredLanguages;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;
use Spaze\SecurityTxt\Violations\SecurityTxtAcknowledgmentsNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtAcknowledgmentsNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtExpired;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresTooLong;
use Spaze\SecurityTxt\Violations\SecurityTxtFieldNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtFieldUriNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtPolicyNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtPolicyNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesCommonMistake;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesEmpty;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesWrongLanguageTags;

final class SecurityTxt implements JsonSerializable
{

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


	public function __construct(
		private readonly SecurityTxtValidationLevel $validationLevel = SecurityTxtValidationLevel::NoInvalidValues,
	) {
	}


	/**
	 * @throws SecurityTxtError
	 * @throws SecurityTxtWarning
	 */
	public function setExpires(Expires $expires): void
	{
		$this->setValue(
			function () use ($expires): void {
				$this->expires = $expires;
			},
			function () use ($expires): void {
				if ($expires->isExpired()) {
					throw new SecurityTxtError(new SecurityTxtExpired());
				}
			},
			function () use ($expires): void {
				if ($expires->inDays() > 366) {
					throw new SecurityTxtWarning(new SecurityTxtExpiresTooLong());
				}
			},
		);
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
	 * @throws SecurityTxtError
	 */
	public function addCanonical(Canonical $canonical): void
	{
		$this->setValue(
			function () use ($canonical): void {
				$this->canonical[] = $canonical;
			},
			function () use ($canonical): void {
				$this->checkUri($canonical->getUri(), SecurityTxtCanonicalNotUri::class, SecurityTxtCanonicalNotHttps::class);
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
	 * @throws SecurityTxtError
	 */
	public function addContact(Contact $contact): void
	{
		$this->setValue(
			function () use ($contact): void {
				$this->contact[] = $contact;
			},
			function () use ($contact): void {
				$this->checkUri($contact->getUri(), SecurityTxtContactNotUri::class, SecurityTxtContactNotHttps::class);
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
	 * @throws SecurityTxtError
	 */
	public function setPreferredLanguages(PreferredLanguages $preferredLanguages): void
	{
		$this->setValue(
			function () use ($preferredLanguages): void {
				$this->preferredLanguages = $preferredLanguages;
			},
			function () use ($preferredLanguages): void {
				if ($preferredLanguages->getLanguages() === []) {
					throw new SecurityTxtError(new SecurityTxtPreferredLanguagesEmpty());
				}
				$wrongLanguages = [];
				foreach ($preferredLanguages->getLanguages() as $key => $value) {
					if (preg_match('/^([a-z]{2,3}(-[a-z0-9]+)*|[xi]-[a-z0-9]+)$/i', $value) !== 1) {
						$wrongLanguages[$key + 1] = $value;
					}
				}
				if ($wrongLanguages !== []) {
					throw new SecurityTxtError(new SecurityTxtPreferredLanguagesWrongLanguageTags($wrongLanguages));
				}
				foreach ($preferredLanguages->getLanguages() as $key => $value) {
					if (preg_match('/^cz-?/i', $value) === 1) {
						throw new SecurityTxtError(new SecurityTxtPreferredLanguagesCommonMistake(
							$key + 1,
							$value,
							preg_replace('/^cz$|cz(-)/i', 'cs$1', $value),
							'the code for Czech language is `cs`, not `cz`',
						));
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
	 * @throws SecurityTxtError
	 */
	public function addAcknowledgments(Acknowledgments $acknowledgments): void
	{
		$this->setValue(
			function () use ($acknowledgments): void {
				$this->acknowledgments[] = $acknowledgments;
			},
			function () use ($acknowledgments): void {
				$this->checkUri($acknowledgments->getUri(), SecurityTxtAcknowledgmentsNotUri::class, SecurityTxtAcknowledgmentsNotHttps::class);
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
	 * @throws SecurityTxtError
	 */
	public function addHiring(Hiring $hiring): void
	{
		$this->setValue(
			function () use ($hiring): void {
				$this->hiring[] = $hiring;
			},
			function () use ($hiring): void {
				$this->checkUri($hiring->getUri(), SecurityTxtHiringNotUri::class, SecurityTxtHiringNotHttps::class);
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
	 * @throws SecurityTxtError
	 */
	public function addPolicy(Policy $policy): void
	{
		$this->setValue(
			function () use ($policy): void {
				$this->policy[] = $policy;
			},
			function () use ($policy): void {
				$this->checkUri($policy->getUri(), SecurityTxtPolicyNotUri::class, SecurityTxtPolicyNotHttps::class);
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
	 * @throws SecurityTxtError
	 */
	public function addEncryption(Encryption $encryption): void
	{
		$this->setValue(
			function () use ($encryption): void {
				$this->encryption[] = $encryption;
			},
			function () use ($encryption): void {
				$this->checkUri($encryption->getUri(), SecurityTxtEncryptionNotUri::class, SecurityTxtEncryptionNotHttps::class);
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
	 * @param (callable(): void)|null $warnings
	 * @return void
	 */
	private function setValue(callable $setValue, callable $validator, ?callable $warnings = null): void
	{
		if ($this->validationLevel === SecurityTxtValidationLevel::AllowInvalidValuesSilently) {
			$setValue();
			return;
		}
		if ($this->validationLevel === SecurityTxtValidationLevel::AllowInvalidValues) {
			$setValue();
			$validator();
		} else {
			$validator();
			$setValue();
		}
		if ($warnings !== null) {
			$warnings();
		}
	}


	/**
	 * @param class-string<SecurityTxtFieldNotUri> $notUriError
	 * @param class-string<SecurityTxtFieldUriNotHttps> $notHttpsError
	 * @throws SecurityTxtError
	 */
	private function checkUri(string $uri, string $notUriError, string $notHttpsError): void
	{
		$scheme = parse_url($uri, PHP_URL_SCHEME);
		if ($scheme === false || $scheme === null) {
			throw new SecurityTxtError(new $notUriError($uri));
		}
		if (strtolower($scheme) === 'http') {
			throw new SecurityTxtError(new $notHttpsError($uri));
		}
	}


	/**
	 * @return array<string, mixed>
	 */
	#[Override]
	public function jsonSerialize(): array
	{
		return [
			'expires' => $this->getExpires(),
			'signatureVerifyResult' => $this->getSignatureVerifyResult(),
			'preferredLanguages' => $this->getPreferredLanguages(),
			'canonical' => $this->getCanonical(),
			'contact' => $this->getContact(),
			'acknowledgments' => $this->getAcknowledgments(),
			'hiring' => $this->getHiring(),
			'policy' => $this->getPolicy(),
			'encryption' => $this->getEncryption(),
		];
	}

}
