<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use BackedEnum;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxtHost;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Tester\Assert;
use Tester\TestCase;
use Throwable;
use Uri\WhatWg\Url;

require __DIR__ . '/../bootstrap.php';

/**
 * A stored result carries a class name and the arguments its constructor was called with, bar an exception's `$previous`, and a decoder replays it by calling that
 * constructor again. So the wire format is not a set of keys, it is these signatures: rename a class, reorder a parameter, add a required one, change what a type means,
 * and a blob written before the change stops being readable while `jsonSerialize()` goes on writing the same two keys, which is what this file is here to notice.
 *
 * `SecurityTxtJson::FORMAT_VERSION` is what announces that, so a diff touching this list is a decision about bumping it, not a fixture to re-record. Its docblock says when.
 * Adding a class does not bump it, but not because nothing can meet one: the Lambda and the site deploy separately, so a newer writer really can hand an older decoder a
 * result naming a class it does not have, and `class_exists()` refuses the whole blob. Bumping would be worse, an older decoder would then refuse every result the
 * newer one writes rather than the few that name the new class, and a refused result is a cache miss to check again. Changing a class that already shipped is the break
 * this number is for.
 *
 * @testCase
 */
final class SecurityTxtWireContractTest extends TestCase
{

	/**
	 * @return array<string, string>
	 */
	private function getContract(): array
	{
		return [
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtCannotOpenUrlException' => '(string $url, array $redirects, ?string $ipAddress = NULL, ?Spaze\\SecurityTxt\\Fetcher\\SecurityTxtIpAddressType $ipAddressType = NULL, ?string $error = NULL, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtCannotOpenUrlExtensionNotLoadedException' => '(string $url, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtCannotOpenUrlUserAgentInvalidException' => '(string $url, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtCannotParseHostnameException' => '(string $url, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtConnectedToWrongIpAddressException' => '(string $expectedIpAddress, string $connectedToIpAddress, string $url, array $redirects, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtHostIpAddressInvalidException' => '(Spaze\\SecurityTxt\\SecurityTxtHost $host, string $ip, Spaze\\SecurityTxt\\Fetcher\\SecurityTxtIpAddressType $ipAddressType, string $url, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtHostIpAddressNotFoundException' => '(string $url, Spaze\\SecurityTxt\\SecurityTxtHost $host, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtHostIpAddressNotPublicException' => '(Spaze\\SecurityTxt\\SecurityTxtHost $host, string $ip, string $url, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtHostNotFoundException' => '(string $url, Spaze\\SecurityTxt\\SecurityTxtHost $host, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtNoHttpCodeException' => '(string $url, array $redirects, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtNoLocationHeaderException' => '(string $url, int $httpCode, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtNotFoundException' => '(array $securityTxtUrls, string $wellKnownUrl, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtOnlyIpv6HostButIpv6DisabledException' => '(Spaze\\SecurityTxt\\SecurityTxtHost $host, string $ipv6, string $url, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtTooManyRedirectsException' => '(string $url, array $redirects, int $maxAllowed, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtUrlNotFoundException' => '(string $url, int $code, string $ipAddress, Spaze\\SecurityTxt\\Fetcher\\SecurityTxtIpAddressType $ipAddressType, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Fetcher\\Exceptions\\SecurityTxtUrlUnsupportedSchemeException' => '(string $url, array $redirects, ?Throwable $previous = NULL)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtAcknowledgmentsNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtAcknowledgmentsNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtBugBountyWrongCase' => '(string $value)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtBugBountyWrongValue' => '(string $value)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtCanonicalNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtCanonicalNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtCanonicalUriMismatch' => '(string $uri, array $canonicalUris)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtContactNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtContactNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtContentNotUtf8' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtContentTypeInvalid' => '(string $uri, ?string $contentType)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtContentTypeWrongCharset' => '(string $uri, string $contentType, ?string $charsetParameter)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtCsafNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtCsafNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtCsafWrongFile' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtEncryptionNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtEncryptionNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtExpired' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtExpiresOldFormat' => '(string $correctValue)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtExpiresSoon' => '(int $inDays)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtExpiresTooLong' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtExpiresWrongFormat' => '(?string $correctValue = NULL)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtFieldNotCoveredBySignature' => '(string $fieldName)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtFileLocationNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtFileLocationNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtHiringNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtHiringNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtLineNoEol' => '(string $line)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtMultipleBugBounty' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtMultipleExpires' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtMultiplePreferredLanguages' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtNoContact' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtNoExpires' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtPolicyNotHttps' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtPolicyNotUri' => '(string $uri)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtPossibelFieldTypo' => '(string $fieldName, string $suggestion, string $line)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtPreferredLanguagesCommonMistake' => '(int $position, string $mistake, ?string $correctValue, Spaze\\SecurityTxt\\Violations\\SecurityTxtPreferredLanguagesCommonMistakeReason $reason)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtPreferredLanguagesEmpty' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtPreferredLanguagesSeparatorNotComma' => '(array $wrongSeparators, array $languages)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtPreferredLanguagesWrongLanguageTags' => '(array $wrongLanguages)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtSignatureCannotVerify' => '(string $message, string $code, string $source, string $libraryMessage)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtSignatureExtensionNotLoaded' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtSignatureInvalid' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtSignatureMultipleCleartextHeaders' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtSignedButNoCanonical' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtTopLevelDiffers' => '(string $wellKnownContents, string $topLevelContents)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtTopLevelPathOnly' => '()',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtUnknownField' => '(string $fieldName, string $line)',
			'Spaze\\SecurityTxt\\Violations\\SecurityTxtWellKnownPathOnly' => '()',
		];
	}


	/**
	 * Keyed by the fully qualified name, which is what the wire stores and what `class_exists()` resolves: a short name would let two classes in different namespaces share
	 * an entry, and would call a namespace move no change at all when to a decoder it is a rename.
	 *
	 * @return list<class-string>
	 */
	private function getReplayableClasses(): array
	{
		$classes = [];
		foreach ([['Fetcher/Exceptions', SecurityTxtFetcherException::class], ['Violations', SecurityTxtSpecViolation::class]] as [$dir, $base]) {
			$namespace = new ReflectionClass($base)->getNamespaceName();
			$files = glob(__DIR__ . '/../../src/' . $dir . '/*.php');
			assert(is_array($files));
			foreach ($files as $file) {
				$class = $namespace . '\\' . basename($file, '.php');
				assert(class_exists($class)); // A file whose class is named otherwise would be skipped silently, and this test only exists to notice things
				$reflection = new ReflectionClass($class);
				if ($reflection->isAbstract() || !$reflection->isSubclassOf($base)) {
					continue;
				}
				$classes[] = $class;
			}
		}
		sort($classes);
		return $classes;
	}


	/**
	 * @return array<string, string>
	 */
	private function getSignatures(): array
	{
		$signatures = [];
		foreach ($this->getReplayableClasses() as $class) {
			$params = [];
			foreach (new ReflectionClass($class)->getConstructor()?->getParameters() ?? [] as $parameter) {
				$type = $parameter->getType();
				// Names are in, though a list is replayed positionally and a rename moves nothing: they are the only thing that tells two parameters of one type apart, so without
				// them swapping a pair, and the array that stores them, reads as no change while a blob written before the swap replays transposed. A rename failing is the
				// price, and the message below says that alone is not a break. The variadic marker and the default do change it. `$previous` is pinned too, even
				// though no blob carries one, an exception passes it to the parent by name and a replayed one is unchained: what matters is where it sits, since moving it
				// ahead of another parameter would have the spread bind a stored value into it
				$default = '';
				if ($parameter->isDefaultValueAvailable()) {
					$default = ' = ' . str_replace("\n", '', var_export($parameter->getDefaultValue(), true));
				}
				$params[] = ($type === null ? 'mixed' : (string)$type) . ' ' . ($parameter->isVariadic() ? '...' : '') . '$' . $parameter->getName() . $default;
			}
			$signatures[$class] = '(' . implode(', ', $params) . ')';
		}
		return $signatures;
	}


	/**
	 * A signature says what the constructor takes; it does not say that the `constructorParams` a subclass hands its parent still line up with it. Swap two entries in that
	 * array and the signature is untouched, every stored result replays into a `TypeError`, and a suite that only pins signatures stays green. So each class is built,
	 * serialized and replayed here, over every concrete one rather than a hand-kept list, because the ones such a list had been missing were exactly the ones with
	 * no round trip anywhere.
	 */


	/**
	 * The wire is the call that built the object, bar an exception's `$previous`, and nothing else. A field is worth storing only if the decoder reads it, and the decoder reads the class and the arguments:
	 * everything an object answers, the message, the how-to-fix, the format, the values, the correct value, the spec references, its constructor computes from those. Storing
	 * any of it would be a second copy that a reworded message or a changed rule can leave disagreeing with the first, and nothing would ever read it to notice.
	 *
	 * Asserted over every class rather than one of each, because `jsonSerialize()` is deliberately not `final`: a subclass writing an extra key harms nothing, the decoder
	 * reads two and ignores the rest, and taking an overridable public method away from a consumer to save a loop here would not be a trade worth making.
	 */
	public function testTheWireCarriesTheCallAndNothingElse(): void
	{
		foreach ($this->getReplayableClasses() as $class) {
			$built = new ReflectionClass($class)->newInstanceArgs($this->getConstructorArguments($class));
			assert($built instanceof SecurityTxtFetcherException || $built instanceof SecurityTxtSpecViolation);
			Assert::same(['class', 'params'], array_keys($built->jsonSerialize()), "{$class} writes something other than the call");
		}
	}


	public function testEveryClassReplaysIntoWhatItWas(): void
	{
		$json = new SecurityTxtJson(new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider()));
		$checked = 0;
		foreach ($this->getReplayableClasses() as $class) {
			$built = new ReflectionClass($class)->newInstanceArgs($this->getConstructorArguments($class));
			assert($built instanceof SecurityTxtFetcherException || $built instanceof SecurityTxtSpecViolation);
			$wire = json_decode((string)json_encode($built), true);
			assert(is_array($wire));
			$replayed = $built instanceof SecurityTxtFetcherException
				? $json->createFetcherExceptionFromJsonValues(['error' => $wire])
				: $json->createViolationsFromJsonValues([$wire])[0];
			Assert::same($built::class, $replayed::class);
			// Every accessor, not just the message: a constructor argument that stops reaching `constructorParams` is lost on replay while the class, the message and the
			// re-serialized params can all still match, which is exactly what a value the message does not mention looks like when it goes missing
			Assert::same($this->getAccessorValues($built), $this->getAccessorValues($replayed), "{$class} does not replay into an equivalent object");
			Assert::same($built->jsonSerialize(), $replayed->jsonSerialize(), "{$class} does not re-serialize to what it was");
			$checked++;
		}
		Assert::same(count($this->getReplayableClasses()), $checked);
	}


	/**
	 * What an object answers, for comparing one against its replay. Out of it: what an exception reports about where it was thrown, which differs by construction site, and
	 * `getPrevious()`, which is deliberately never serialized so a replayed exception is unchained. `getCode()` stays in, it comes off the params like anything else.
	 *
	 * @return array<string, mixed>
	 */
	private function getAccessorValues(object $object): array
	{
		$skip = ['getFile', 'getLine', 'getTrace', 'getTraceAsString', 'getPrevious'];
		$values = [];
		foreach (new ReflectionClass($object)->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
			$name = $method->getName();
			if ($method->isStatic() || $method->getNumberOfParameters() !== 0 || in_array($name, $skip, true)) {
				continue;
			}
			if (!str_starts_with($name, 'get') && !str_starts_with($name, 'is')) {
				continue;
			}
			$values[$name] = $this->normalize($method->invoke($object));
		}
		ksort($values);
		return $values;
	}


	private function normalize(mixed $value): mixed
	{
		if ($value instanceof SecurityTxtHost) {
			return $value->getUnicode();
		}
		if ($value instanceof Url) {
			return $value->toUnicodeString();
		}
		if ($value instanceof BackedEnum) {
			return $value->value;
		}
		if (is_array($value)) {
			return array_map($this->normalize(...), $value);
		}
		return is_object($value) ? $value::class : $value;
	}


	/**
	 * Values a constructor will accept, by type. The ones that validate their input get theirs by hand.
	 *
	 * @param class-string $class
	 * @return list<mixed>
	 */
	private function getConstructorArguments(string $class): array
	{
		if ($class === SecurityTxtPossibelFieldTypo::class) {
			return ['Contct', SecurityTxtField::Contact->value, 'Contct: https://example.com/'];
		}
		if ($class === SecurityTxtNotFoundException::class) {
			$url = 'https://example.com/.well-known/security.txt';
			return [[$url => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 404, 'redirects' => [], 'html' => false, 'truncated' => false]], $url];
		}
		// Every argument is distinct, including two of the same type next to each other: fed the same value twice, a constructor that stores its params in the wrong order
		// replays into an object that looks identical, and the swap this test exists to catch would pass
		$arguments = [];
		foreach (new ReflectionClass($class)->getConstructor()?->getParameters() ?? [] as $position => $parameter) {
			$type = $parameter->getType();
			$name = $type instanceof ReflectionNamedType ? $type->getName() : '';
			$arguments[] = match (true) {
				$name === Throwable::class => null,
				$name === SecurityTxtHost::class => SecurityTxtHost::fromString("h\u{E1}\u{10D}ky.example"),
				is_subclass_of($name, BackedEnum::class) => $name::cases()[0],
				$name === 'int' => 400 + $position,
				$name === 'array' => ["https://example.com/{$parameter->getName()}"],
				default => "https://example.com/{$parameter->getName()}",
			};
		}
		return $arguments;
	}


	public function testTheConstructorsAreTheWireFormat(): void
	{
		$signatures = $this->getSignatures();
		Assert::true($signatures !== []); // Would pass without testing anything if the glob above was wrong
		$contract = $this->getContract();
		$changes = [];
		foreach ($signatures as $class => $signature) {
			if (!isset($contract[$class])) {
				$changes[] = "{$class} is new, add it to getContract():\n    '{$class}' => '{$signature}',";
			} elseif ($contract[$class] !== $signature) {
				$changes[] = "{$class} changed:\n    was '{$contract[$class]}'\n    now '{$signature}'";
			}
		}
		foreach ($contract as $class => $signature) {
			if (!isset($signatures[$class])) {
				$changes[] = "{$class} is gone, a stored result naming it cannot be replayed at all:\n    was '{$signature}'";
			}
		}
		// The count is what is compared and the classes go in the description, because a compared value is truncated in the output and a description is not: printing two
		// lists of every signature there is, and a `diff` command, is what this is for avoiding
		Assert::same(0, count($changes), $changes === [] ? '' : sprintf(
			"%s\n\nThe constructors are the wire format, see %s::FORMAT_VERSION. Names are pinned only because they tell two parameters of one type apart, so a rename trips "
			. "this too: update the line and do not bump, nothing replays differently. Nor does a parameter added at the end with a default, or a new class, see this file's "
			. "docblock for why. Bump first and update the line second when an older stored result could not replay into what is there now.\n",
			implode("\n\n", $changes),
			SecurityTxtJson::class,
		));
	}

}

new SecurityTxtWireContractTest()->run();
