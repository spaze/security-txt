<?php
/** @noinspection HttpUrlsUsage */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use DateTimeImmutable;
use Override;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsProvider;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsRecords;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherUrl;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureGnuPgProvider;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalUriMismatch;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeInvalid;
use Spaze\SecurityTxt\Violations\SecurityTxtExpired;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresTooLong;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelDiffers;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtCheckHostTest extends TestCase
{

	private SecurityTxtSplitLines $splitLines;
	private SecurityTxtParser $parser;
	private SecurityTxtUrlParser $urlParser;
	private SecurityTxtCheckHostResultFactory $checkHostResultFactory;
	private DateTimeImmutable $validExpires;
	private string $validExpiresLine;


	public function __construct()
	{
		$validator = new SecurityTxtValidator();
		$gnuPgProvider = new SecurityTxtSignatureGnuPgProvider();
		$signature = new SecurityTxtSignature($gnuPgProvider);
		$expiresFactory = new SecurityTxtExpiresFactory();
		$pregSplitProvider = new SecurityTxtPregSplitProvider();
		$this->splitLines = new SecurityTxtSplitLines($pregSplitProvider);
		$this->parser = new SecurityTxtParser($validator, $signature, $expiresFactory, $this->splitLines, $pregSplitProvider);
		$this->urlParser = new SecurityTxtUrlParser();
		$this->checkHostResultFactory = new SecurityTxtCheckHostResultFactory();
		$this->validExpires = new DateTimeImmutable('+6 months');
		$this->validExpiresLine = 'Expires:' . $this->validExpires->format(DATE_RFC3339);
	}


	public function testCheckHost(): void
	{
		$onUrlCalled = $onFinalUrlCalled = $onRedirectCalled = $onUrlNotFoundCalled = $onIsExpiredCalled = $onExpiresCalled = $onHostCalled = $onValidSignatureCalled = false;
		$onFetchErrorCalled = $onFetchWarningCalled = $onLineErrorCalled = $onLineWarningCalled = $onFileErrorCalled = $onFileWarningCalled = false;
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		{$this->validExpiresLine}
		Canonical: https://foo.bar.example/.well-known/security.txt
		-----BEGIN PGP SIGNATURE-----

		iJIEARYKADoWIQSvbhd14xH/eOkR59x/h5ABqcj1CgUCaH7y/xwcc3RpbGwudGVz
		dHNAbGlicmFyeS5leGFtcGxlAAoJEH+HkAGpyPUKRvEA/2cVGZs54ieQ7s1nSTla
		6O+JHJNaLOf3llvGRi55gW+BAQCDVLTj2q7cbHPS78lD/uvsgFI3NVWwZx8m72sx
		SmjCCQ==
		=bZYA
		-----END PGP SIGNATURE-----
		EOT . "\n";

		$checkHost = $this->getCheckHost(200, ['content-type' => 'text/plain; charset=utf-8'], $contents);
		$checkHost->addOnUrl(function () use (&$onUrlCalled): void {
			$onUrlCalled = true;
		});
		$checkHost->addOnFinalUrl(function () use (&$onFinalUrlCalled): void {
			$onFinalUrlCalled = true;
		});
		$checkHost->addOnRedirect(function () use (&$onRedirectCalled): void {
			$onRedirectCalled = true;
		});
		$checkHost->addOnUrlNotFound(function () use (&$onUrlNotFoundCalled): void {
			$onUrlNotFoundCalled = true;
		});
		$checkHost->addOnIsExpired(function () use (&$onIsExpiredCalled): void {
			$onIsExpiredCalled = true;
		});
		$checkHost->addOnExpires(function () use (&$onExpiresCalled): void {
			$onExpiresCalled = true;
		});
		$checkHost->addOnHost(function () use (&$onHostCalled): void {
			$onHostCalled = true;
		});
		$checkHost->addOnValidSignature(function () use (&$onValidSignatureCalled): void {
			$onValidSignatureCalled = true;
		});
		$checkHost->addOnFetchError(function () use (&$onFetchErrorCalled): void {
			$onFetchErrorCalled = true;
		});
		$checkHost->addOnFetchWarning(function () use (&$onFetchWarningCalled): void {
			$onFetchWarningCalled = true;
		});
		$checkHost->addOnLineError(function () use (&$onLineErrorCalled): void {
			$onLineErrorCalled = true;
		});
		$checkHost->addOnLineWarning(function () use (&$onLineWarningCalled): void {
			$onLineWarningCalled = true;
		});
		$checkHost->addOnFileError(function () use (&$onFileErrorCalled): void {
			$onFileErrorCalled = true;
		});
		$checkHost->addOnFileWarning(function () use (&$onFileWarningCalled): void {
			$onFileWarningCalled = true;
		});

		$result = $checkHost->check('https://foo.bar.example/');
		Assert::same($contents, $result->getContents());
		Assert::false($result->getIsExpired());
		Assert::true($onUrlCalled);
		Assert::true($onFinalUrlCalled);
		Assert::false($onRedirectCalled);
		Assert::false($onUrlNotFoundCalled);
		Assert::false($onIsExpiredCalled);
		Assert::true($onExpiresCalled);
		Assert::true($onHostCalled);
		Assert::true($onValidSignatureCalled);
		Assert::false($onFetchErrorCalled);
		Assert::false($onFetchWarningCalled);
		Assert::false($onLineErrorCalled);
		Assert::false($onLineWarningCalled);
		Assert::false($onFileErrorCalled);
		Assert::false($onFileWarningCalled);
		Assert::same([], $result->getFetchWarnings());
		Assert::same([], $result->getFetchErrors());
		Assert::same([], $result->getLineWarnings());
		Assert::same([], $result->getLineErrors());
		Assert::same([], $result->getFileWarnings());
		Assert::same([], $result->getFileErrors());
	}


	public function testCheckHostLineErrorWarning(): void
	{
		$contents = "Contact: foo@example.com\nExpires: " . $this->validExpires->modify('+10 years')->format(DATE_RFC3339) . "\n";
		$checkHost = $this->getCheckHost(200, [], $contents);
		$onLineErrorCalled = $onLineWarningCalled = false;
		$checkHost->addOnLineError(function () use (&$onLineErrorCalled): void {
			$onLineErrorCalled = true;
		});
		$checkHost->addOnLineWarning(function () use (&$onLineWarningCalled): void {
			$onLineWarningCalled = true;
		});
		$result = $checkHost->check('https://example.com');
		Assert::equal([1 => [new SecurityTxtContactNotUri('foo@example.com')]], $result->getLineErrors());
		Assert::equal([2 => [new SecurityTxtExpiresTooLong()]], $result->getLineWarnings());
		Assert::true($onLineErrorCalled);
		Assert::true($onLineWarningCalled);
	}


	public function testCheckHostRedirect(): void
	{
		$contents = "Contact: foo@example.com\nExpires: " . $this->validExpires->modify('+10 years')->format(DATE_RFC3339) . "\n";
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(301, ['location' => 'https://example.net/'], 'redirect', false, '1.1.1.0', DNS_A),
			new SecurityTxtFetcherResponse(200, [], $contents, false, '1.1.1.0', DNS_A),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(new SecurityTxtDnsRecords('192.0.2.1', null)), 1);
		$checkHost = new SecurityTxtCheckHost($this->parser, $this->urlParser, $fetcher, $this->checkHostResultFactory);

		$onRedirectCalled = false;
		$checkHost->addOnRedirect(function () use (&$onRedirectCalled): void {
			$onRedirectCalled = true;
		});
		$result = $checkHost->check('https://example.com');
		Assert::equal([1 => [new SecurityTxtContactNotUri('foo@example.com')]], $result->getLineErrors());
		Assert::equal([2 => [new SecurityTxtExpiresTooLong()]], $result->getLineWarnings());
		Assert::true($onRedirectCalled);
	}


	public function testCheckHostNotFound(): void
	{
		$checkHost = $this->getCheckHost(404, [], 'not found');
		$onUrlNotFoundCalled = false;
		$checkHost->addOnUrlNotFound(function () use (&$onUrlNotFoundCalled): void {
			$onUrlNotFoundCalled = true;
		});
		Assert::throws(function () use ($checkHost): void {
			$checkHost->check('https://example.com');
		}, SecurityTxtNotFoundException::class);
		Assert::true($onUrlNotFoundCalled);
	}


	public function testCheckExpiredNoEol(): void
	{
		$contents = 'Expires: ' . $this->validExpires->modify('-10 years')->format(DATE_RFC3339);
		$checkHost = $this->getCheckHost(200, [], $contents);
		$onIsExpiredCalled = false;
		$checkHost->addOnIsExpired(function () use (&$onIsExpiredCalled): void {
			$onIsExpiredCalled = true;
		});
		$result = $checkHost->check('https://example.com');
		Assert::true($result->getIsExpired());
		Assert::equal([1 => [new SecurityTxtLineNoEol($contents), new SecurityTxtExpired()]], $result->getLineErrors());
		Assert::true($onIsExpiredCalled);
	}


	public function testCheckFetchErrorWarning(): void
	{
		$contentType = 'pineapple/pizza';
		$url = 'https://example.com/.well-known/security.txt';

		$wellKnownContents = $this->validExpiresLine . "\n";
		$topLevelContents = 'Content differs';
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(200, ['content-type' => $contentType], $wellKnownContents, false, '1.1.1.0', DNS_A),
			new SecurityTxtFetcherResponse(200, ['content-type' => $contentType], $topLevelContents, false, '1.1.1.0', DNS_A),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(new SecurityTxtDnsRecords('192.0.2.1', null)), 1);
		$checkHost = new SecurityTxtCheckHost($this->parser, $this->urlParser, $fetcher, $this->checkHostResultFactory);

		$onFetchErrorCalled = $onFetchWarningCalled = false;
		$checkHost->addOnFetchError(function () use (&$onFetchErrorCalled): void {
			$onFetchErrorCalled = true;
		});
		$checkHost->addOnFetchWarning(function () use (&$onFetchWarningCalled): void {
			$onFetchWarningCalled = true;
		});
		$result = $checkHost->check($url);
		Assert::equal([new SecurityTxtContentTypeInvalid($url, $contentType)], $result->getFetchErrors());
		Assert::equal([new SecurityTxtTopLevelDiffers($wellKnownContents, $topLevelContents)], $result->getFetchWarnings());
		Assert::true($onFetchErrorCalled);
		Assert::true($onFetchWarningCalled);
	}


	public function testCheckFileErrorWarning(): void
	{
		$canonical1 = "https://1.example/.well-known/security.txt";
		$canonical2 = "https://2.example/.well-known/security.txt";
		$contents = "{$this->validExpiresLine}\nCanonical: {$canonical1}\nCanonical: {$canonical2}\n";
		$checkHost = $this->getCheckHost(200, [], $contents);

		$onFileErrorCalled = $onFileWarningCalled = false;
		$checkHost->addOnFileError(function () use (&$onFileErrorCalled): void {
			$onFileErrorCalled = true;
		});
		$checkHost->addOnFileWarning(function () use (&$onFileWarningCalled): void {
			$onFileWarningCalled = true;
		});
		$url = 'https://example.com/.well-known/security.txt';
		$result = $checkHost->check($url);
		Assert::equal([new SecurityTxtNoContact()], $result->getFileErrors());
		Assert::equal([new SecurityTxtCanonicalUriMismatch($url, [$canonical1, $canonical2])], $result->getFileWarnings());
		Assert::true($onFileErrorCalled);
		Assert::true($onFileWarningCalled);
	}


	/**
	 * @param array<lowercase-string, string> $lowercaseHeaders
	 */
	private function getCheckHost(int $httpCode, array $lowercaseHeaders, string $contents): SecurityTxtCheckHost
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse($httpCode, $lowercaseHeaders, $contents, false, '1.1.1.0', DNS_A));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(new SecurityTxtDnsRecords('192.0.2.1', null)), 1);
		return new SecurityTxtCheckHost($this->parser, $this->urlParser, $fetcher, $this->checkHostResultFactory);
	}


	private function getHttpClient(SecurityTxtFetcherResponse ...$fetcherResponse): SecurityTxtFetcherHttpClient
	{
		return new class (...$fetcherResponse) implements SecurityTxtFetcherHttpClient {

			/**
			 * @var list<SecurityTxtFetcherResponse>
			 */
			private array $fetcherResponse;
			private int $position = 0;
			private int $lastKey = 0;


			public function __construct(SecurityTxtFetcherResponse ...$fetcherResponse)
			{
				$this->fetcherResponse = array_values($fetcherResponse);
				$this->lastKey = count($fetcherResponse) - 1;
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, string $host, string $ipAddress, int $ipAddressType): SecurityTxtFetcherResponse
			{
				return $this->fetcherResponse[$this->position++] ?? $this->fetcherResponse[$this->lastKey];
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
			public function getRecords(string $url, string $host): SecurityTxtDnsRecords
			{
				return $this->dnsRecords;
			}

		};
	}

}

(new SecurityTxtCheckHostTest())->run();
