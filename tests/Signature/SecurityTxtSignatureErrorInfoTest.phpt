<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtSignatureErrorInfoTest extends TestCase
{

	public function testGetters(): void
	{
		$errorInfo = new SecurityTxtSignatureErrorInfo(null, null, null, null);
		Assert::null($errorInfo->getMessage());
		Assert::same('<null>', $errorInfo->getMessageAsString());
		Assert::null($errorInfo->getCode());
		Assert::same('<null>', $errorInfo->getCodeAsString());
		Assert::null($errorInfo->getSource());
		Assert::same('<null>', $errorInfo->getSourceAsString());
		Assert::null($errorInfo->getLibraryMessage());
		Assert::same('<null>', $errorInfo->getLibraryMessageAsString());

		$errorInfo = new SecurityTxtSignatureErrorInfo('message', 303, 'source', 'library message');
		Assert::same('message', $errorInfo->getMessage());
		Assert::same('message', $errorInfo->getMessageAsString());
		Assert::same(303, $errorInfo->getCode());
		Assert::same('303', $errorInfo->getCodeAsString());
		Assert::same('source', $errorInfo->getSource());
		Assert::same('source', $errorInfo->getSourceAsString());
		Assert::same('library message', $errorInfo->getLibraryMessage());
		Assert::same('library message', $errorInfo->getLibraryMessageAsString());

		$errorInfo = new SecurityTxtSignatureErrorInfo(false, 303, 'source', 'library message');
		Assert::false($errorInfo->getMessage());
		Assert::same('<false>', $errorInfo->getMessageAsString());
	}

}

(new SecurityTxtSignatureErrorInfoTest())->run();
