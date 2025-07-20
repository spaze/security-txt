<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use Override;
use SensitiveParameter;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotCreateSignatureException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtSigningKeyBadPassphraseException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtSigningKeyNoPassphraseSetException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtUnknownSigningKeyException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtUnusableSigningKeyException;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureProvider;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtSignatureTest extends TestCase
{

	public function testSign(): void
	{
		$signatureProvider = new class () implements SecurityTxtSignatureProvider {

			private bool $addSignKeyReturnValue;

			private SecurityTxtSignatureErrorInfo $errorInfo;

			private string|false $signReturnValue;


			public function __construct()
			{
				$this->addSignKeyReturnValue = true;
				$this->errorInfo = new SecurityTxtSignatureErrorInfo(false, 0, 'Unspecified source', 'Success');
				$this->signReturnValue = '';
			}


			#[Override]
			public function addSignKey(string $fingerprint, #[SensitiveParameter] string $passphrase = ''): bool
			{
				return $this->addSignKeyReturnValue;
			}


			public function setAddSignKeyReturnValue(bool $value): void
			{
				$this->addSignKeyReturnValue = $value;
			}


			#[Override]
			public function getErrorInfo(): SecurityTxtSignatureErrorInfo
			{
				return $this->errorInfo;
			}


			public function setErrorInfo(SecurityTxtSignatureErrorInfo $errorInfo): void
			{
				$this->errorInfo = $errorInfo;
			}


			#[Override]
			public function sign(string $text): false|string
			{
				return $this->signReturnValue;
			}


			public function setSignReturnValue(false|string $signReturnValue): void
			{
				$this->signReturnValue = $signReturnValue;
			}

		};

		$signature = new SecurityTxtSignature($signatureProvider);

		$signatureProvider->setSignReturnValue('signed');
		Assert::same('signed', $signature->sign('foo', 'fingerprint', 'passphrase'));

		$signatureProvider->setAddSignKeyReturnValue(false);
		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo('no passphrase set', 1, 'no pass source', 'no pass lib error'));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key with pass');
		}, SecurityTxtSigningKeyNoPassphraseSetException::class, 'Cannot create a signature, key sign key with pass requires a passphrase');

		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo('bad passphrase', 67108875, 'bad pass source', 'bad pass lib error'));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key with pass', 'bad pass');
		}, SecurityTxtSigningKeyBadPassphraseException::class, 'Cannot create a signature, bad passphrase for key sign key with pass');

		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo('unknown key', 117456895, 'unknown key source', 'unknown key lib error'));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'unknown sign key', 'irrelevant');
		}, SecurityTxtUnknownSigningKeyException::class, 'Cannot create a signature, unknown key unknown sign key');

		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo(false, 31336, 'unusable key source', 'unusable key lib error'));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'unusable sign key', 'irrelevant');
		}, SecurityTxtUnusableSigningKeyException::class, 'Unusable signing key unusable sign key: <false>; code: 31336, source: unusable key source, library message: unusable key lib error', 31336);

		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo('unusable key', 31336, 'unusable key source', 'unusable key lib error'));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'unusable sign key', 'irrelevant');
		}, SecurityTxtUnusableSigningKeyException::class, 'Unusable signing key unusable sign key: unusable key; code: 31336, source: unusable key source, library message: unusable key lib error', 31336);

		$signatureProvider->setAddSignKeyReturnValue(true);
		$signatureProvider->setSignReturnValue(false);
		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo(false, 1, 'sign source', 'sign lib error'));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key 1', 'passphrase');
		}, SecurityTxtCannotCreateSignatureException::class, 'Cannot create a signature using key sign key 1: <false>; code: 1, source: sign source, library message: sign lib error');

		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo('sign error', 1, 'sign source', 'sign lib error'));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key 1', 'passphrase');
		}, SecurityTxtCannotCreateSignatureException::class, 'Cannot create a signature using key sign key 1: sign error; code: 1, source: sign source, library message: sign lib error');

		$signatureProvider->setAddSignKeyReturnValue(true);
		$signatureProvider->setSignReturnValue('signed');
		Assert::same('signed', $signature->sign('foo', 'multiple add', 'passphrase'));
		$signatureProvider->setAddSignKeyReturnValue(false);
		$signatureProvider->setErrorInfo(new SecurityTxtSignatureErrorInfo('invalid signers found', 0, 'Unspecified source', 'Success'));
		Assert::noError(function () use ($signature): void {
			Assert::same('signed', $signature->sign('foo', 'multiple add', 'passphrase'));
		});
	}

}

new SecurityTxtSignatureTest()->run();
