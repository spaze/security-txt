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

}
