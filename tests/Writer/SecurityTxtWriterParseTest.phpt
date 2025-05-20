<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\SecurityTxtAcknowledgments;
use Spaze\SecurityTxt\Fields\SecurityTxtCanonical;
use Spaze\SecurityTxt\Fields\SecurityTxtContact;
use Spaze\SecurityTxt\Fields\SecurityTxtEncryption;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Fields\SecurityTxtHiring;
use Spaze\SecurityTxt\Fields\SecurityTxtPolicy;
use Spaze\SecurityTxt\Fields\SecurityTxtPreferredLanguages;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Writer\SecurityTxtWriter;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtWriterParseTest extends TestCase
{

	private SecurityTxtParser $securityTxtParser;
	private SecurityTxtWriter $securityTxtWriter;
	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;


	public function __construct()
	{
		$securityTxtValidator = new SecurityTxtValidator();
		$securityTxtSignature = new SecurityTxtSignature();
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
		$securityTxtSplitLines = new SecurityTxtSplitLines();
		$this->securityTxtParser = new SecurityTxtParser($securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $securityTxtSplitLines);
		$this->securityTxtWriter = new SecurityTxtWriter();
	}


	public function testWriteParse(): void
	{
		$dateTime = new DateTimeImmutable('+2 months midnight');
		$securityTxt = new SecurityTxt();
		$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('https://ack1.example'));
		$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('https://ack2.example'));
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://canonical1.example'));
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://canonical2.example'));
		$securityTxt->addContact(new SecurityTxtContact('https://contact.example'));
		$securityTxt->addContact(SecurityTxtContact::phone('123456'));
		$securityTxt->addContact(SecurityTxtContact::email('email@com.example'));
		$securityTxt->addEncryption(new SecurityTxtEncryption('https://encryption1.example'));
		$securityTxt->addEncryption(new SecurityTxtEncryption('https://encryption2.example'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create($dateTime));
		$securityTxt->addHiring(new SecurityTxtHiring('https://hiring1.example'));
		$securityTxt->addHiring(new SecurityTxtHiring('https://hiring2.example'));
		$securityTxt->addPolicy(new SecurityTxtPolicy('https://policy1.example'));
		$securityTxt->addPolicy(new SecurityTxtPolicy('https://policy2.example'));
		$securityTxt->setPreferredLanguages(new SecurityTxtPreferredLanguages(['en', 'cs']));
		$parsed = $this->securityTxtParser->parseString($this->securityTxtWriter->write($securityTxt));
		Assert::true($parsed->isValid());
		Assert::same([], $parsed->getFileErrors());
		Assert::same([], $parsed->getFileWarnings());
		Assert::same([], $parsed->getLineErrors());
		Assert::same([], $parsed->getLineWarnings());
		Assert::same([], $parsed->getValidateResult()->getErrors());
		Assert::same([], $parsed->getValidateResult()->getWarnings());
		Assert::null($parsed->getSecurityTxt()->getSignatureVerifyResult());
		$expected = ['https://ack1.example', 'https://ack2.example'];
		Assert::same($expected, array_map(fn($a): string => $a->getUri(), $parsed->getSecurityTxt()->getAcknowledgments()));
		$expected = ['https://canonical1.example', 'https://canonical2.example'];
		Assert::same($expected, array_map(fn($c): string => $c->getUri(), $parsed->getSecurityTxt()->getCanonical()));
		$expected = ['https://contact.example', 'tel:123456', 'mailto:email@com.example'];
		Assert::same($expected, array_map(fn($c): string => $c->getUri(), $parsed->getSecurityTxt()->getContact()));
		$expected = ['https://encryption1.example', 'https://encryption2.example'];
		Assert::same($expected, array_map(fn($e): string => $e->getUri(), $parsed->getSecurityTxt()->getEncryption()));
		Assert::same($dateTime->format(DATE_RFC3339), $parsed->getSecurityTxt()->getExpires()?->getDateTime()->format(DATE_RFC3339));
		$expected = ['https://hiring1.example', 'https://hiring2.example'];
		Assert::same($expected, array_map(fn($h): string => $h->getUri(), $parsed->getSecurityTxt()->getHiring()));
		$expected = ['https://policy1.example', 'https://policy2.example'];
		Assert::same($expected, array_map(fn($p): string => $p->getUri(), $parsed->getSecurityTxt()->getPolicy()));
		Assert::same(['en', 'cs'], $parsed->getSecurityTxt()->getPreferredLanguages()?->getLanguages());
	}

}

new SecurityTxtWriterParseTest()->run();
