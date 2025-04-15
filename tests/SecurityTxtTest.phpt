<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\Fields\Contact;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\PreferredLanguages;
use Spaze\SecurityTxt\Fields\SecurityTxtUriField;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtExpired;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresTooLong;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesCommonMistake;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesEmpty;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesWrongLanguageTags;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/bootstrap.php';

/** @testCase */
final class SecurityTxtTest extends TestCase
{

	public function testSetExpires(): void
	{
		$securityTxt = new SecurityTxt();
		$in2Weeks = new Expires(new DateTimeImmutable('+2 weeks'));
		$in3Weeks = new Expires(new DateTimeImmutable('+3 weeks'));
		$securityTxt->setExpires($in2Weeks);
		$securityTxt->setExpires($in3Weeks);
		Assert::equal($in3Weeks, $securityTxt->getExpires());
	}


	/**
	 * @return array<string, array{0:SecurityTxtValidationLevel}>
	 */
	public function getAllowInvalidValues(): array
	{
		return [
			'allow invalid' => [SecurityTxtValidationLevel::AllowInvalidValues],
			'do not allow invalid' => [SecurityTxtValidationLevel::NoInvalidValues],
		];
	}


	/** @dataProvider getAllowInvalidValues */
	public function testSetExpiresTooLong(SecurityTxtValidationLevel $validationLevel): void
	{
		$securityTxt = new SecurityTxt($validationLevel);
		$future = new Expires(new DateTimeImmutable('+1 year +1 month'));
		$e = Assert::throws(function () use ($securityTxt, $future): void {
			$securityTxt->setExpires($future);
		}, SecurityTxtWarning::class);
		assert($e instanceof SecurityTxtWarning);
		Assert::type(SecurityTxtExpiresTooLong::class, $e->getViolation());
		Assert::equal($future, $securityTxt->getExpires());
	}


	public function testSetExpired(): void
	{
		$securityTxt = new SecurityTxt();
		$past = new Expires(new DateTimeImmutable('-1 month'));
		$e = Assert::throws(function () use ($securityTxt, $past): void {
			$securityTxt->setExpires($past);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtExpired::class, $e->getViolation());
		Assert::null($securityTxt->getExpires());

		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValues);
		$past = new Expires(new DateTimeImmutable('-1 month'));
		$e = Assert::throws(function () use ($securityTxt, $past): void {
			$securityTxt->setExpires($past);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtExpired::class, $e->getViolation());
		Assert::equal($past, $securityTxt->getExpires());
	}


	/**
	 * @return array<string, array{0: array<string, class-string<SecurityTxtSpecViolation>|null>, 1: class-string, 2: callable(SecurityTxt):callable, 3: callable(SecurityTxt):(callable():list<SecurityTxtUriField>), 4: callable}>
	 * @noinspection HttpUrlsUsage
	 */
	public function getAddFieldValues(): array
	{
		return [
			'canonical' => [
				[
					'https://example.com/.well-known/security.txt' => null,
					'http://example.com/.well-known/security.txt' => SecurityTxtCanonicalNotHttps::class,
					'ftp://foo.bar.example.net/security.txt' => null,
					'C:\\security.txt' => null,
				],
				Canonical::class,
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->addCanonical(...);
				},
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->getCanonical(...);
				},
				function (Canonical $canonical): string {
					return $canonical->getUri();
				},
			],
			'contact' => [
				[
					'https://example.com/contact' => null,
					'http://example.com/contact' => SecurityTxtContactNotHttps::class,
					'ftp://foo.example.net/contact.txt' => null,
					'mailto:foo@example.com' => null,
					'bar@example.com' => SecurityTxtContactNotUri::class,
					'tel:+1-201-555-0123' => null,
					'+1-201-555-01234' => SecurityTxtContactNotUri::class,
				],
				Contact::class,
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->addContact(...);
				},
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->getContact(...);
				},
				function (Contact $contact): string {
					return $contact->getUri();
				},
			],
		];
	}


	/**
	 * @param array<string, class-string<SecurityTxtSpecViolation>|null> $values
	 * @param class-string $fieldClass
	 * @param callable(SecurityTxt): callable $addFactory
	 * @param callable(SecurityTxt): (callable(): list<SecurityTxtUriField>) $getFieldFactory
	 * @param callable $getValue
	 * @dataProvider getAddFieldValues
	 */
	public function testAddField(array $values, string $fieldClass, callable $addFactory, callable $getFieldFactory, callable $getValue): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxtWithInvalidValues = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValues);
		$allValues = $validValues = [];

		foreach ($values as $value => $violation) {
			$allValues[] = $value;
			if ($violation !== null) {
				$e = Assert::throws(function () use ($securityTxt, $value, $fieldClass, $addFactory): void {
					$addFactory($securityTxt)(new $fieldClass($value));
				}, SecurityTxtError::class);
				assert($e instanceof SecurityTxtError);
				Assert::type($violation, $e->getViolation());
				$e = Assert::throws(function () use ($securityTxtWithInvalidValues, $value, $fieldClass, $addFactory): void {
					$addFactory($securityTxtWithInvalidValues)(new $fieldClass($value));
				}, SecurityTxtError::class);
				assert($e instanceof SecurityTxtError);
				Assert::type($violation, $e->getViolation());
			} else {
				$validValues[] = $value;
				$addFactory($securityTxt)(new $fieldClass($value));
				$addFactory($securityTxtWithInvalidValues)(new $fieldClass($value));
			}
		}

		Assert::same($validValues, array_map($getValue, $getFieldFactory($securityTxt)()));
		Assert::same($allValues, array_map($getValue, $getFieldFactory($securityTxtWithInvalidValues)()));
	}


	/**
	 * @return array<string, array{0: list<string>, 1: class-string<SecurityTxtSpecViolation>|null}>
	 */
	public function getPreferredLanguageValues(): array
	{
		return [
			'no language' => [[], SecurityTxtPreferredLanguagesEmpty::class],
			'empty language' => [[''], SecurityTxtPreferredLanguagesWrongLanguageTags::class],
			'wrong language' => [['a'], SecurityTxtPreferredLanguagesWrongLanguageTags::class],
			'one wrong language' => [['en', 'cs', 'E', 'CS'], SecurityTxtPreferredLanguagesWrongLanguageTags::class],
			'common mistake' => [['en', 'cz'], SecurityTxtPreferredLanguagesCommonMistake::class],
			'alright languages' => [['en', 'cs', 'EN', 'CS'], null],
		];
	}


	/**
	 * @param list<string> $languages
	 * @param class-string<SecurityTxtSpecViolation>|null $violation
	 * @dataProvider getPreferredLanguageValues
	 */
	public function testSetPreferredLanguages(array $languages, ?string $violation): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxtWithInvalidValues = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValues);

		if ($violation !== null) {
			$e = Assert::throws(function () use ($languages, $securityTxt): void {
				$securityTxt->setPreferredLanguages(new PreferredLanguages($languages));
			}, SecurityTxtError::class);
			assert($e instanceof SecurityTxtError);
			Assert::type($violation, $e->getViolation());
			$e = Assert::throws(function () use ($languages, $securityTxtWithInvalidValues): void {
				$securityTxtWithInvalidValues->setPreferredLanguages(new PreferredLanguages($languages));
			}, SecurityTxtError::class);
			assert($e instanceof SecurityTxtError);
			Assert::type($violation, $e->getViolation());
		} else {
			$securityTxt->setPreferredLanguages(new PreferredLanguages($languages));
			$securityTxtWithInvalidValues->setPreferredLanguages(new PreferredLanguages($languages));
		}

		if ($violation !== null) {
			Assert::null($securityTxt->getPreferredLanguages());
		} else {
			Assert::same($languages, $securityTxt->getPreferredLanguages()?->getLanguages());
		}
		Assert::same($languages, $securityTxtWithInvalidValues->getPreferredLanguages()?->getLanguages());
	}


	public function testSecurityTxtValidationLevelDefault(): void
	{
		$securityTxt = new SecurityTxt();
		Assert::throws(function () use ($securityTxt): void {
			$securityTxt->setExpires(new Expires(new DateTimeImmutable('-1 month')));
		}, SecurityTxtError::class, 'The file is considered stale and should not be used');
		Assert::null($securityTxt->getExpires());
	}


	public function testSecurityTxtValidationLevelNoInvalidValues(): void
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::NoInvalidValues);
		Assert::throws(function () use ($securityTxt): void {
			$securityTxt->setExpires(new Expires(new DateTimeImmutable('-1 month')));
		}, SecurityTxtError::class, 'The file is considered stale and should not be used');
		Assert::null($securityTxt->getExpires());
	}


	public function testSecurityTxtValidationLevelAllowInvalidValues(): void
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValues);
		$expires = new DateTimeImmutable('-1 month');
		Assert::throws(function () use ($securityTxt, $expires): void {
			$securityTxt->setExpires(new Expires($expires));
		}, SecurityTxtError::class, 'The file is considered stale and should not be used');
		Assert::equal($expires, $securityTxt->getExpires()?->getDateTime());
	}


	public function testSecurityTxtValidationLevelAllowInvalidValuesSilently(): void
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$expires = new DateTimeImmutable('-1 month');
		Assert::noError(function () use ($securityTxt, $expires): void {
			$securityTxt->setExpires(new Expires($expires));
		});
		Assert::equal($expires, $securityTxt->getExpires()?->getDateTime());
	}

}

new SecurityTxtTest()->run();
