<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtPhpDnsProvider;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtOnlyIpv6HostButIpv6DisabledException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherCurlClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressValidator;
use Spaze\SecurityTxt\Fetcher\SecurityTxtRedirects;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureGnuPgProvider;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
use function Spaze\SecurityTxt\Test\gnupgHomeDir;
use function Spaze\SecurityTxt\Test\needsInternet;

require __DIR__ . '/../bootstrap.php';

/**
 * The hosts checked by hand before a release, each one for a path nothing else reaches: one that only answers over IPv6, one that redirects and then has no file, one that
 * redirects to a web page, one on an internationalized name, one whose file lives on another host entirely, one that sends a relative `Location`, one with violations
 * against numbered lines, one whose other location is a decoy, and one carrying a cleartext signature.
 *
 * What they are is real, and what a real host serves changes: a file gets fixed, an expiry counts down, `litacka.cz` answers from a different address between two fetches
 * of one run. So nothing here asserts a message, a date, an address or a violation a host happens to have today, which is what a stored baseline of the output could never
 * keep for a week. Each host instead asserts the one thing it is in the list for, which is the path it drives rather than the file it serves, and one host is one test so
 * that a host which stops driving its path says so in red rather than going quietly stale, which is what `www.swisscom.ch` did while it was listed for warnings. That is
 * also why `@testCase` sits in the file's opening docblock and not this one: Tester reads annotations out of the first docblock in a file and no other, and without it all
 * nine run in one process, where the first host to drift ends the run and takes the other eight with it unreported.
 * Every check runs with IPv6 off, because otherwise which path a host takes depends on whether the machine has a v6 route: `404media.co` redirects to a name that has
 * one, and reaching it decides between a missing file and a connection that never opens. The cost is that an IPv6 fetch is never exercised, and that the host listed for
 * answering only over IPv6 reaches the disabled path instead, which is a path worth having either way.
 */
final class SecurityTxtCheckHostSmokeTest extends TestCase
{

	private function getCheckHost(): SecurityTxtCheckHost
	{
		$urlParser = new SecurityTxtUrlParser();
		$splitProvider = new SecurityTxtPregSplitProvider();
		$splitLines = new SecurityTxtSplitLines($splitProvider);
		$fetcher = new SecurityTxtFetcher(new SecurityTxtFetcherCurlClient(), $urlParser, $splitLines, new SecurityTxtPhpDnsProvider(), new SecurityTxtIpAddressValidator());
		$signature = new SecurityTxtSignature(new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir()));
		$parser = new SecurityTxtParser(new SecurityTxtValidator(), $signature, new SecurityTxtExpiresFactory(), $splitLines, $splitProvider);
		return new SecurityTxtCheckHost($parser, $fetcher, new SecurityTxtCheckHostResultFactory(), $urlParser);
	}


	/**
	 * `loopsofzen.uk` publishes no address other than an IPv6 one, so with IPv6 off it is the one host here that reaches the refusal rather than a lookup that finds nothing,
	 * and the two are worth telling apart because only one of them is this library deciding something.
	 */
	public function testAHostWithOnlyAnIpv6AddressIsRefusedRatherThanNotFound(): void
	{
		needsInternet();
		$e = Assert::throws(function (): void {
			$this->getCheckHost()->check(new Url('https://loopsofzen.uk'), noIpv6: true);
		}, SecurityTxtOnlyIpv6HostButIpv6DisabledException::class);
		assert($e instanceof SecurityTxtOnlyIpv6HostButIpv6DisabledException);
		Assert::contains('loopsofzen.uk', $e->getMessage());
	}


	/**
	 * Both locations redirect off `404media.co` onto its `www` name and 404 there, so the exception says nothing a host with no file at all would not also say. What this host
	 * covers is that the chain is carried into the exception, and pinning where it went is what notices the day the redirect stops happening and the row stops being this.
	 */
	public function testARedirectEndingInNoFileCarriesTheChain(): void
	{
		needsInternet();
		$e = Assert::throws(function (): void {
			$this->getCheckHost()->check(new Url('https://404media.co'), noIpv6: true);
		}, SecurityTxtNotFoundException::class);
		assert($e instanceof SecurityTxtNotFoundException);
		Assert::same([
			'https://404media.co/.well-known/security.txt' => ['https://www.404media.co/.well-known/security.txt'],
			'https://404media.co/security.txt' => ['https://www.404media.co/security.txt'],
		], $e->getAllRedirects());
	}


	/**
	 * Both of `www.litacka.cz`'s locations redirect to `pidlitacka.cz`, which answers with a web page, so unlike every other host that ends up not found the fetch itself
	 * succeeded and the content is what failed. The message is what says so, because whether a response was a web page or merely too long to be a `security.txt` is decided
	 * on the way into the exception and kept nowhere else: `getIpAddresses()` carries the status but is keyed by address, so the two locations collapse into one entry
	 * whenever the CDN answers both from the same one, and a 200 alone is also what a file too long to read would leave behind.
	 */
	public function testAWebPageWhereTheFileShouldBeIsFetchedAndThenRejected(): void
	{
		needsInternet();
		$e = Assert::throws(function (): void {
			$this->getCheckHost()->check(new Url('https://www.litacka.cz'), noIpv6: true);
		}, SecurityTxtNotFoundException::class);
		assert($e instanceof SecurityTxtNotFoundException);
		Assert::contains('regular HTML page', $e->getMessage());
	}


	/**
	 * The host reads as itself everywhere a person sees it, and the A-labels it is looked up by appear nowhere. `háčkyčárky.cz` is the regression host for the lookup that
	 * used to hand `dns_get_record()` the readable name and find nothing.
	 */
	public function testAnInternationalizedHostReadsAsItselfThroughout(): void
	{
		needsInternet();
		$host = "h\u{E1}\u{10D}ky\u{10D}\u{E1}rky.cz";
		$e = Assert::throws(function () use ($host): void {
			$this->getCheckHost()->check(new Url("https://{$host}/"), noIpv6: true);
		}, SecurityTxtFetcherException::class);
		assert($e instanceof SecurityTxtFetcherException);
		// Resolved, so the failure is about the file rather than the name: the A-label lookup worked
		Assert::type(SecurityTxtNotFoundException::class, $e);
		Assert::contains($host, $e->getMessage());
		Assert::notContains('xn--', $e->getMessage());
	}


	/**
	 * A file found on another host is still a check of the host that was asked for: `www.gov.uk` redirects off itself, and the result has to go on naming `www.gov.uk` while
	 * reporting where it ended up. That a violation about the response names the URL that answered instead is `SecurityTxtFetcherTest::testAContentTypeIsReportedAtTheUrlThatSentIt`,
	 * which builds the redirect itself rather than waiting for a third party to serve a bad header.
	 */
	public function testAFileFoundOnAnotherHostStillNamesTheHostAsked(): void
	{
		needsInternet();
		$result = $this->getCheckHost()->check(new Url('https://www.gov.uk'), noIpv6: true);
		Assert::notSame('www.gov.uk', $result->getFinalUrl()->getAsciiHost());
		Assert::same('www.gov.uk', $result->getHost()->getAscii());
	}


	/**
	 * `www.nic.cz` answers `/security.txt` with a bare `Location: /security.txt/`, the only relative one in the list, and what is recorded is that header resolved against the
	 * URL it came from. A fetcher that kept it as it arrived would store a path where a URL belongs, and the recorded destination is the only place that would show it. Note
	 * what this cannot see: the raw header is not kept, so the day `nic.cz` starts sending an absolute `Location` the recorded chain is identical and this still passes while
	 * the only relative one in the list has quietly gone.
	 */
	public function testARelativeLocationIsRecordedResolved(): void
	{
		needsInternet();
		$result = $this->getCheckHost()->check(new Url('https://www.nic.cz/'), noIpv6: true);
		$redirects = array_map(fn(SecurityTxtRedirects $chain): array => $chain->toStrings(), $result->getRedirects());
		Assert::same(['https://www.nic.cz/security.txt/'], $redirects['https://www.nic.cz/security.txt'] ?? []);
	}


	/**
	 * The only host here whose file has violations against numbered lines, so it is the only one that runs them through a check end to end. Which violations they are is
	 * `kb.cz`'s to change and is not asserted, but one of each kind is: errors and warnings are two collections reached by two callers, and a row listed for both stops
	 * being that the day either goes quiet. Red here is the point rather than a false alarm, it says the corpus wants another host, not that this one broke.
	 */
	public function testAFileWithViolationsOnNumberedLines(): void
	{
		needsInternet();
		$result = $this->getCheckHost()->check(new Url('https://www.kb.cz/'), noIpv6: true);
		Assert::notSame([], $result->getLineErrors());
		Assert::notSame([], $result->getLineWarnings());
	}


	/**
	 * Both locations answer and the right one has to win: `www.swisscom.ch` serves the file at `/.well-known/security.txt`, while `/security.txt` redirects to an error page
	 * that returns 200 and four kilobytes of HTML. A fetcher that took whichever responded first would report a web page as a `security.txt`, and `litacka.cz` cannot catch
	 * that because both of its locations end up at the same page. Nothing about the winning response is flagged either, which is the one place a header this library did not
	 * write gets read: `charset=UTF-8`, spelled in a case the comparison has to ignore.
	 */
	public function testTheWellKnownLocationWinsOverADecoy(): void
	{
		needsInternet();
		$result = $this->getCheckHost()->check(new Url('https://www.swisscom.ch/'), noIpv6: true);
		Assert::same('https://www.swisscom.ch/.well-known/security.txt', $result->getFinalUrl()->toUnicodeString());
		Assert::same([], $result->getFetchErrors());
	}


	/**
	 * The only signed file in the list, so the only one that runs the whole path: fetched over the wire, recognized as a cleartext signature, split, and handed to gnupg. What
	 * comes back is the issuer the signature names, not a verdict on it. That key is deliberately absent from `tests/gnupg`, which is the ordinary case when checking someone
	 * else's file and the one `SecurityTxtSignature::isSignatureKindaOkay()` exists to allow, so gnupg reports `KEY_MISSING` and reads the fingerprint out of the packet. The
	 * fingerprint is still worth asserting because it is a key this library's author controls: it moves when that key is rotated, deliberately, and not when a host edits a file.
	 */
	public function testASignedFileReportsTheIssuerItNames(): void
	{
		needsInternet();
		$result = $this->getCheckHost()->check(new Url('https://www.michalspacek.cz/'), noIpv6: true);
		Assert::same('4BD4C403AF2F9FCCB151FE61B64BDD6E464AB529', $result->getSecurityTxt()->getSignatureVerifyResult()?->getKeyFingerprint());
	}

}

new SecurityTxtCheckHostSmokeTest()->run();
