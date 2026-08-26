<?php
/** @noinspection HttpUrlsUsage */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use DateTimeImmutable;
use Override;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsProvider;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsRecords;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherUrl;
use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressValidator;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxtHost;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureGnuPgProvider;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
use function Spaze\SecurityTxt\Test\gnupgHomeDir;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtCheckHostCliTest extends TestCase
{

	private ?int $exitStatus = null;
	private string $expires;


	public function __construct()
	{
		$this->expires = (new DateTimeImmutable('-42 days'))->format(DATE_RFC3339);
	}


	public function testCheckErrorWarning(): void
	{
		$contents = "Contact: mailto:foo@example.com\nExpires: {$this->expires}\n";
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain'], $contents, false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(302, ['location' => 'https://nah.example/'], 'yes but', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'yeah nah', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url('https://example.com'), null, true, true, true, true, true, false, 'Help I need some<body>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;90m[Info][0m Parsing security.txt for [1mexample.com[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/.well-known/security.txt[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/security.txt[0m
		[1;90m[Info][0m Redirected from [1mhttps://example.com/security.txt[0m to [1mhttps://nah.example/[0m
		[1;90m[Info][0m Not found [1mhttps://nah.example/[0m
		[1;90m[Info][0m Using [1mhttps://example.com/.well-known/security.txt[0m
		[1;31m[Error][0m The file at https://example.com/.well-known/security.txt has a correct Content-Type of text/plain but the charset=utf-8 parameter is missing (How to fix: Add a charset=utf-8 parameter, e.g. text/plain; charset=utf-8)
		[1;31m[Error][0m on line [1m2[0m: The file is considered stale and should not be used (How to fix: The Expires field should contain a date and time in the future formatted according to the Internet profile of ISO 8601 as defined in RFC 3339, e.g. {$this->getExpiresExample()})
		[1m[Warning][0m security.txt not found at the top-level path (How to fix: Redirect the top-level file to the one under the /.well-known/ path)
		[1;31m[Error][0m [1;31mThe file has expired 42 days ago[0m ({$this->expires})
		[1;31m[Error][0m [1;31mThe file is invalid[0m
		EOT;
		Assert::same($expected . "\n", $output);
		Assert::same(CheckExitStatus::Error->value, $this->exitStatus);
	}


	public function testCheckViolationValuesPrintAsTheyRead(): void
	{
		// Colors off and no ESC bytes, so what is asserted here is the values, not the markup
		// The ten minutes are a buffer: formatting truncates sub-seconds, so a bare '+42 days' diffs back to 41 as soon as any time passes, which fails only on a loaded runner
		$expires = (new DateTimeImmutable('+42 days 10 minutes'))->format(DATE_RFC3339);
		$contents = "Contact: HTTP://\u{4F8B}\u{3048}.jp/contact\nCanonical: https://other.example/\nExpires: {$expires}\n";
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain; charset=utf-8'], $contents, false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'not found', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);
		$this->exitStatus = null;

		ob_start();
		$checkHostCli->check(new Url("https://\u{4F8B}\u{3048}.jp"), null, false, false, false, false, true, false, 'Help');
		$output = ob_get_clean();
		$expected = "[Info] Parsing security.txt for \u{4F8B}\u{3048}.jp\n"
			. "[Info] Using https://\u{4F8B}\u{3048}.jp/.well-known/security.txt\n"
			// The correct value is there to be copied into a file, so it has to read as a URL, percent encoded it would be neither readable nor usable
			. "[Error] on line 1: If the Contact field indicates a web URI, then it must begin with \"https://\""
			. " (How to fix: Make sure the Contact field points to an https:// URI, e.g. https://\u{4F8B}\u{3048}.jp/contact)\n"
			// A URL among the message values reads as itself with the ASCII host alongside, which is what composing the formats is for
			. "[Warning] The file was fetched from https://\u{4F8B}\u{3048}.jp/.well-known/security.txt"
			. " but the Canonical field (https://other.example/) does not list this URI"
			. " (How to fix: Add a new Canonical field with the URI https://\u{4F8B}\u{3048}.jp/.well-known/security.txt,"
			. " or ensure the file is fetched from the listed canonical URI)\n"
			. "[OK] The file will expire in 42 days ({$expires})\n"
			. "[Error] The file is invalid\n";
		Assert::same($expected, $output);
		Assert::same(CheckExitStatus::Error->value, $this->exitStatus);
	}


	public function testCheckErrorWarningVerboseThenNonVerbose(): void
	{
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain; charset=utf-8'], "Contact: mailto:foo@example.com\nExpires: {$this->expires}\n", false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(302, ['location' => 'https://nah1.example/'], 'yes but', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'yeah nah', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain; charset=utf-8'], "Contact: mailto:foo@two.example\n", false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(302, ['location' => 'https://nah2.example/'], 'yes but', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'yeah nah', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url('https://verbose.example'), null, true, true, true, true, true, false, 'Help I need some<body>');
		$checkHostCli->check(new Url('https://non-verbose.example'), null, true, false, true, true, true, false, 'Help I need some<body>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;90m[Info][0m Parsing security.txt for [1mverbose.example[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://verbose.example/.well-known/security.txt[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://verbose.example/security.txt[0m
		[1;90m[Info][0m Redirected from [1mhttps://verbose.example/security.txt[0m to [1mhttps://nah1.example/[0m
		[1;90m[Info][0m Not found [1mhttps://nah1.example/[0m
		[1;90m[Info][0m Using [1mhttps://verbose.example/.well-known/security.txt[0m
		[1;31m[Error][0m on line [1m2[0m: The file is considered stale and should not be used (How to fix: The Expires field should contain a date and time in the future formatted according to the Internet profile of ISO 8601 as defined in RFC 3339, e.g. {$this->getExpiresExample()})
		[1m[Warning][0m security.txt not found at the top-level path (How to fix: Redirect the top-level file to the one under the /.well-known/ path)
		[1;31m[Error][0m [1;31mThe file has expired 42 days ago[0m ({$this->expires})
		[1;31m[Error][0m [1;31mThe file is invalid[0m
		[1;90m[Info][0m Parsing security.txt for [1mnon-verbose.example[0m
		[1;90m[Info][0m Using [1mhttps://non-verbose.example/.well-known/security.txt[0m
		[1;31m[Error][0m The Expires field must always be present (How to fix: Add an Expires field with a date and time in the future formatted according to the Internet profile of ISO 8601 as defined in RFC 3339, e.g. {$this->getExpiresExample()})
		[1m[Warning][0m security.txt not found at the top-level path (How to fix: Redirect the top-level file to the one under the /.well-known/ path)
		[1;31m[Error][0m [1;31mThe file is invalid[0m
		EOT;
		Assert::same($expected . "\n", $output);
		Assert::same(CheckExitStatus::Error->value, $this->exitStatus);
	}


	public function testCheckExpiresSoonStrictMode(): void
	{
		$expires = (new DateTimeImmutable('+5 days 10 minutes'))->format(DATE_RFC3339);

		$contents = "Contact: mailto:foo@example.com\nExpires: {$expires}\n";
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain; charset=utf-8'], $contents, false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], $contents, false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url('https://example.com'), 10, true, true, true, false, true, false, 'Help I need some<body>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;90m[Info][0m Parsing security.txt for [1mexample.com[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/.well-known/security.txt[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/security.txt[0m
		[1;90m[Info][0m Not found [1mhttps://example.com/security.txt[0m
		[1;90m[Info][0m Using [1mhttps://example.com/.well-known/security.txt[0m
		[1m[Warning][0m on line [1m2[0m: The file will be considered stale in 5 days (How to fix: Update the value of the Expires field, e.g. {$this->getExpiresExample()})
		[1;32m[OK][0m The file will expire in 5 days ({$expires})
		[1;31m[Error][0m [1;31mThe file is invalid[0m
		EOT;
		Assert::same($expected . "\n", $output);
		Assert::same(CheckExitStatus::Error->value, $this->exitStatus);
	}


	public function testCheckOkSigned(): void
	{
		$expires = (new DateTimeImmutable('+5 days 10 minutes'))->format(DATE_RFC3339);
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		Expires: {$expires}
		Canonical: https://example.com/.well-known/security.txt
		-----BEGIN PGP SIGNATURE-----

		iJIEARYKADoWIQSvbhd14xH/eOkR59x/h5ABqcj1CgUCaH7y/xwcc3RpbGwudGVz
		dHNAbGlicmFyeS5leGFtcGxlAAoJEH+HkAGpyPUKRvEA/2cVGZs54ieQ7s1nSTla
		6O+JHJNaLOf3llvGRi55gW+BAQCDVLTj2q7cbHPS78lD/uvsgFI3NVWwZx8m72sx
		SmjCCQ==
		=bZYA
		-----END PGP SIGNATURE-----
		EOT . "\n";

		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain; charset=utf-8'], $contents, false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], $contents, false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url('https://example.com'), null, true, true, true, false, true, false, 'Help I need some<body>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;90m[Info][0m Parsing security.txt for [1mexample.com[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/.well-known/security.txt[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/security.txt[0m
		[1;90m[Info][0m Not found [1mhttps://example.com/security.txt[0m
		[1;90m[Info][0m Using [1mhttps://example.com/.well-known/security.txt[0m
		[1;32m[OK][0m The file will expire in 5 days ({$expires})
		[1;32m[OK][0m Signature valid, key AF6E1775E311FF78E911E7DC7F879001A9C8F50A, signed on 2025-07-22T02:10:07+00:00
		[1;32m[OK][0m [1;32mThe file is valid[0m
		EOT;
		Assert::same($expected . "\n", $output);
		Assert::same(CheckExitStatus::Ok->value, $this->exitStatus);
	}


	public function testCheckNotFound(): void
	{
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(404, [], 'not found', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'not found', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url('https://example.com'), null, true, true, true, false, true, false, 'Help I need some<body>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;90m[Info][0m Parsing security.txt for [1mexample.com[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/.well-known/security.txt[0m
		[1;90m[Info][0m Not found [1mhttps://example.com/.well-known/security.txt[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/security.txt[0m
		[1;90m[Info][0m Not found [1mhttps://example.com/security.txt[0m
		[1;31m[Error][0m Can't read security.txt: https://example.com/.well-known/security.txt (1.1.1.0) => 404, https://example.com/security.txt (1.1.1.0) => 404
		EOT;
		Assert::same($expected . "\n", $output);
		Assert::same(CheckExitStatus::FileError->value, $this->exitStatus);
	}


	public function testCheckShowHelpThenNotFound(): void
	{
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(404, [], 'not found', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'not found', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url('https://example.com'), null, true, false, true, false, true, true, 'Help I need some1');
		$checkHostCli->check(new Url('https://example.com'), null, true, true, true, false, true, false, 'Help I need some<body>');
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;90m[Info][0m Help I need some1
		[1;90m[Info][0m Parsing security.txt for [1mexample.com[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/.well-known/security.txt[0m
		[1;90m[Info][0m Not found [1mhttps://example.com/.well-known/security.txt[0m
		[1;90m[Info][0m Loading security.txt from [1mhttps://example.com/security.txt[0m
		[1;90m[Info][0m Not found [1mhttps://example.com/security.txt[0m
		[1;31m[Error][0m Can't read security.txt: https://example.com/.well-known/security.txt (1.1.1.0) => 404, https://example.com/security.txt (1.1.1.0) => 404
		EOT;
		Assert::same($expected . "\n", $output);
		Assert::same(CheckExitStatus::FileError->value, $this->exitStatus);
	}


	public function testCheckNotFoundIdnHostNoColors(): void
	{
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(404, [], 'not found', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'not found', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url("https://\u{4F8B}\u{3048}.jp"), null, false, false, true, false, true, false, 'Help');
		$output = ob_get_clean();
		// The host and the URLs read as themselves, the IP address and the code do not parse and stay as they are
		$expected = "[Info] Parsing security.txt for \u{4F8B}\u{3048}.jp\n"
			. "[Error] Can't read security.txt: https://\u{4F8B}\u{3048}.jp/.well-known/security.txt (1.1.1.0) => 404,"
			. " https://\u{4F8B}\u{3048}.jp/security.txt (1.1.1.0) => 404\n";
		Assert::same($expected, $output);
		Assert::same(CheckExitStatus::FileError->value, $this->exitStatus);
	}


	public function testCheckHelpNoColors(): void
	{
		$httpClient = $this->getHttpClient();
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(null, null, false, false, true, false, true, false, 'Help I need some<body>');
		$output = ob_get_clean();
		Assert::same("[Info] Help I need some<body>\n", $output);
		Assert::same(CheckExitStatus::NoFile->value, $this->exitStatus);
	}


	public function testCheckHelpOption(): void
	{
		$httpClient = $this->getHttpClient();
		$checkHostCli = $this->getCheckHostCli($httpClient);

		ob_start();
		$checkHostCli->check(new Url('https://example.com'), null, false, false, true, false, true, true, 'Help I need some<body>');
		$output = ob_get_clean();
		Assert::same("[Info] Help I need some<body>\n", $output);
		Assert::same(CheckExitStatus::Ok->value, $this->exitStatus);
	}


	private function getCheckHostCli(SecurityTxtFetcherHttpClient $httpClient): SecurityTxtCheckHostCli
	{
		$urlParser = new SecurityTxtUrlParser();
		$validator = new SecurityTxtValidator();
		$gnuPgProvider = new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir());
		$signature = new SecurityTxtSignature($gnuPgProvider);
		$expiresFactory = new SecurityTxtExpiresFactory();
		$pregSplitProvider = new SecurityTxtPregSplitProvider();
		$splitLines = new SecurityTxtSplitLines($pregSplitProvider);
		$ipAddressValidator = new SecurityTxtIpAddressValidator();
		$parser = new SecurityTxtParser($validator, $signature, $expiresFactory, $splitLines, $pregSplitProvider);
		$fetcher = new SecurityTxtFetcher($httpClient, $urlParser, $splitLines, $this->getDnsProvider(new SecurityTxtDnsRecords('1.1.1.0', null)), $ipAddressValidator, 1);
		$checkHostResultFactory = new SecurityTxtCheckHostResultFactory();
		$checkHost = new SecurityTxtCheckHost($parser, $fetcher, $checkHostResultFactory);
		return new SecurityTxtCheckHostCli(
			new ConsolePrinter(),
			$checkHost,
			function (int $status): void {
				$this->exitStatus = $status;
			},
		);
	}


	private function getHttpClient(SecurityTxtFetcherResponse ...$fetcherResponse): SecurityTxtFetcherHttpClient
	{
		return new class (...$fetcherResponse) implements SecurityTxtFetcherHttpClient {

			/**
			 * @var list<SecurityTxtFetcherResponse>
			 */
			private array $fetcherResponse;
			private int $position = 0;


			public function __construct(SecurityTxtFetcherResponse ...$fetcherResponse)
			{
				$this->fetcherResponse = array_values($fetcherResponse);
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, SecurityTxtHost $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
			{
				return $this->fetcherResponse[$this->position++];
			}

		};
	}


	private function getDnsProvider(SecurityTxtDnsRecords $dnsRecords): SecurityTxtDnsProvider
	{
		return new readonly class ($dnsRecords) implements SecurityTxtDnsProvider {

			public function __construct(private SecurityTxtDnsRecords $dnsRecords)
			{
			}


			#[Override]
			public function getRecords(Url $url, SecurityTxtHost $host): SecurityTxtDnsRecords
			{
				return $this->dnsRecords;
			}

		};
	}


	private function getExpiresExample(): string
	{
		return (new DateTimeImmutable('+1 year midnight -1 sec'))->format(SecurityTxtExpires::FORMAT);
	}

}

(new SecurityTxtCheckHostCliTest())->run();
