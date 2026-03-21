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
		\Tester\Environment::skip(sprintf(
			'The test uses the Internet, to not skip the test case run it with `%s=%s`',
			'TEST_CASE_RUNNER_INCLUDE_SKIPPED',
			'1',
		));
	}

}
