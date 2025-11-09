<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use DateTimeImmutable;
use DateTimeZone;
use Override;
use ReflectionProperty;
use SensitiveParameter;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotCreateSignatureException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotCreateSignatureExtensionNotLoadedException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotVerifySignatureException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtSignatureException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtSigningKeyBadPassphraseException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtSigningKeyNoPassphraseSetException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtUnknownSigningKeyException;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtUnusableSigningKeyException;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureProvider;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureInvalid;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtSignatureTest extends TestCase
{

	public function testSign(): void
	{
		$signature = new SecurityTxtSignature($this->getSignatureProvider(signReturnValue: 'signed'));
		Assert::same('signed', $signature->sign('foo', 'fingerprint', 'passphrase'));

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: false, errorInfo: new SecurityTxtSignatureErrorInfo('data signing failed', 67109041, 'no pass source', 'no pass lib error')));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key with pass');
		}, SecurityTxtSigningKeyNoPassphraseSetException::class, 'Cannot create a signature, key sign key with pass requires a passphrase');

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: false, errorInfo: new SecurityTxtSignatureErrorInfo('bad passphrase', 67108875, 'bad pass source', 'bad pass lib error')));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key with pass', 'bad pass');
		}, SecurityTxtSigningKeyBadPassphraseException::class, 'Cannot create a signature, bad passphrase for key sign key with pass');

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: false, errorInfo: new SecurityTxtSignatureErrorInfo('unknown key', 117456895, 'unknown key source', 'unknown key lib error')));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'unknown sign key', 'irrelevant');
		}, SecurityTxtUnknownSigningKeyException::class, 'Cannot create a signature, unknown key unknown sign key');

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: false, errorInfo: new SecurityTxtSignatureErrorInfo(false, 31336, 'unusable key source', 'unusable key lib error')));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'unusable sign key', 'irrelevant');
		}, SecurityTxtUnusableSigningKeyException::class, 'Unusable signing key unusable sign key: <false>; code: 31336, source: unusable key source, library message: unusable key lib error', 31336);

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: false, errorInfo: new SecurityTxtSignatureErrorInfo('unusable key', 31336, 'unusable key source', 'unusable key lib error')));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'unusable sign key', 'irrelevant');
		}, SecurityTxtUnusableSigningKeyException::class, 'Unusable signing key unusable sign key: unusable key; code: 31336, source: unusable key source, library message: unusable key lib error', 31336);

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: true, errorInfo: new SecurityTxtSignatureErrorInfo(false, 1, 'sign source', 'sign lib error'), signReturnValue: false));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key 1', 'passphrase');
		}, SecurityTxtCannotCreateSignatureException::class, 'Cannot create a signature using key sign key 1: <false>; code: 1, source: sign source, library message: sign lib error');

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: true, errorInfo: new SecurityTxtSignatureErrorInfo('sign error', 1, 'sign source', 'sign lib error'), signReturnValue: false));
		Assert::throws(function () use ($signature): void {
			$signature->sign('foo', 'sign key 1', 'passphrase');
		}, SecurityTxtCannotCreateSignatureException::class, 'Cannot create a signature using key sign key 1: sign error; code: 1, source: sign source, library message: sign lib error');

		$signature = new SecurityTxtSignature($this->getSignatureProvider(addSignKeyReturnValue: true, signReturnValue: 'signed'));
		Assert::same('signed', $signature->sign('foo', 'multiple add', 'passphrase'));

		$property = new ReflectionProperty($signature, 'signatureProvider');
		$property->setValue($signature, $this->getSignatureProvider(addSignKeyReturnValue: false, errorInfo: new SecurityTxtSignatureErrorInfo('invalid signers found', 0, 'Unspecified source', 'Success'), signReturnValue: 'signed'));
		Assert::noError(function () use ($signature): void {
			Assert::same('signed', $signature->sign('foo', 'multiple add', 'passphrase'));
		});
	}


	public function testVerify(): void
	{
		$time = 0x123456789;
		$signature = new SecurityTxtSignature($this->getSignatureProvider(verifySignatureInfo: new SecurityTxtSignatureVerifySignatureInfo(GNUPG_SIGSUM_GREEN, 'fingerprint1337', $time)));
		Assert::noError(function () use ($signature, &$result): void {
			$result = $signature->verify('signed');
		});
		assert($result instanceof SecurityTxtSignatureVerifyResult);
		Assert::same('fingerprint1337', $result->getKeyFingerprint());
		Assert::same('fingerprint1337', $result->getKeyId());
		Assert::same('rint1337', $result->getShortKeyId());
		Assert::equal((new DateTimeImmutable("@{$time}"))->setTimezone(new DateTimeZone('UTC')), $result->getDate());

		$signature = new SecurityTxtSignature($this->getSignatureProvider(verifySignatureInfo: new SecurityTxtSignatureVerifySignatureInfo(GNUPG_SIGSUM_KEY_MISSING, 'fingerprint1337', $time)));
		Assert::noError(function () use ($signature, &$result): void {
			$result = $signature->verify('signed');
		});
		$signature = new SecurityTxtSignature($this->getSignatureProvider(verifySignatureInfo: new SecurityTxtSignatureVerifySignatureInfo(GNUPG_SIGSUM_KEY_MISSING + 1, 'fingerprint1337', $time)));
		Assert::noError(function () use ($signature, &$result): void {
			$result = $signature->verify('signed');
		});
		$signature = new SecurityTxtSignature($this->getSignatureProvider(verifySignatureInfo: new SecurityTxtSignatureVerifySignatureInfo(GNUPG_SIGSUM_RED - 1, 'fingerprint1337', $time)));
		Assert::noError(function () use ($signature, &$result): void {
			$result = $signature->verify('signed');
		});
		$signature = new SecurityTxtSignature($this->getSignatureProvider(verifySignatureInfo: new SecurityTxtSignatureVerifySignatureInfo(GNUPG_SIGSUM_VALID /* you wish */, 'fingerprint1337', $time)));
		$e = Assert::throws(function () use ($signature): void {
			$signature->verify('signature invalid');
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtSignatureInvalid::class, $e->getViolation());

		$signature = new SecurityTxtSignature($this->getSignatureProvider(verifyThrows: new SecurityTxtCannotCreateSignatureExtensionNotLoadedException()));
		$e = Assert::throws(function () use ($signature): void {
			$signature->verify('the gnupg extension is not loaded');
		}, SecurityTxtWarning::class);
		assert($e instanceof SecurityTxtWarning);
		Assert::type(SecurityTxtSignatureExtensionNotLoaded::class, $e->getViolation());

		$signature = new SecurityTxtSignature($this->getSignatureProvider(verifyThrows: new SecurityTxtCannotVerifySignatureException(null, new SecurityTxtSignatureErrorInfo('msg', 1336, null, null))));
		$e = Assert::throws(function () use ($signature): void {
			$signature->verify('gnupg::verify returns invalid array');
		}, SecurityTxtCannotVerifySignatureException::class);
		assert($e instanceof SecurityTxtCannotVerifySignatureException);
		Assert::same('Cannot verify signature: msg; code: 1336, source: <null>, library message: <null>', $e->getMessage());
	}


	private function getSignatureProvider(
		?bool $addSignKeyReturnValue = null,
		?SecurityTxtSignatureErrorInfo $errorInfo = null,
		string|false|null $signReturnValue = null,
		?SecurityTxtSignatureVerifySignatureInfo $verifySignatureInfo = null,
		?SecurityTxtSignatureException $verifyThrows = null,
	): SecurityTxtSignatureProvider {
		if ($addSignKeyReturnValue === null) {
			$addSignKeyReturnValue = true;
		}
		if ($errorInfo === null) {
			$errorInfo = new SecurityTxtSignatureErrorInfo(false, 0, 'Unspecified source', 'Success');
		}
		if ($signReturnValue === null) {
			$signReturnValue = '';
		}
		if ($verifySignatureInfo === null) {
			$verifySignatureInfo = new SecurityTxtSignatureVerifySignatureInfo(0, 'fingerprint', time());
		}
		return new readonly class ($addSignKeyReturnValue, $errorInfo, $signReturnValue, $verifySignatureInfo, $verifyThrows) implements SecurityTxtSignatureProvider {

			public function __construct(
				private bool $addSignKeyReturnValue,
				private SecurityTxtSignatureErrorInfo $errorInfo,
				private string|false $signReturnValue,
				private SecurityTxtSignatureVerifySignatureInfo $verifySignatureInfo,
				private ?SecurityTxtSignatureException $verifyThrows = null,
			) {
			}


			/**
			 * @throws void
			 */
			#[Override]
			public function addSignKey(string $fingerprint, #[SensitiveParameter] string $passphrase = ''): bool
			{
				return $this->addSignKeyReturnValue;
			}


			/**
			 * @throws void
			 */
			#[Override]
			public function getErrorInfo(): SecurityTxtSignatureErrorInfo
			{
				return $this->errorInfo;
			}


			/**
			 * @throws void
			 */
			#[Override]
			public function sign(string $text): false|string
			{
				return $this->signReturnValue;
			}


			#[Override]
			public function verify(string $text): SecurityTxtSignatureVerifySignatureInfo
			{
				if ($this->verifyThrows !== null) {
					throw $this->verifyThrows;
				}
				return $this->verifySignatureInfo;
			}

		};
	}

}

(new SecurityTxtSignatureTest())->run();
