<?php
declare(strict_types = 1);

namespace {

	require __DIR__ . '/../vendor/autoload.php';
	\Tester\Environment::setup();

}

namespace Spaze\SecurityTxt\Test {

	function needsInternet(): void
	{
		if (getenv('TEST_CASE_RUNNER_INCLUDE_SKIPPED') === '1') {
			return;
		}
		\Tester\Environment::skip('The test uses the Internet, to not skip the test case run it with TEST_CASE_RUNNER_INCLUDE_SKIPPED=1, or run composer tester-include-skipped to run all skipped tests');
	}


	function skipIfExtensionLoaded(string $extension): void
	{
		if (extension_loaded($extension)) {
			if (getenv('TEST_CASE_RUNNER_FORCE_EXTENSIONS_NOT_LOADED') === '1') {
				\Tester\Assert::fail("The {$extension} extension must not be loaded for this test, run with the php-unix-no-extensions.ini configuration, or run composer tester-no-extensions to run all similar tests");
			} else {
				\Tester\Environment::skip('Run this test with the php-unix-no-extensions.ini configuration, or run composer tester-no-extensions to run all similar tests');
			}
		}
	}

}
