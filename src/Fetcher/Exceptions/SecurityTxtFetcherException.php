<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Exception;
use JsonSerializable;
use Override;
use Spaze\SecurityTxt\SecurityTxtHost;
use Spaze\SecurityTxt\SecurityTxtPrintableValue;
use Throwable;

abstract class SecurityTxtFetcherException extends Exception implements JsonSerializable
{

	/** @var list<string|SecurityTxtHost> */
	private readonly array $messageValues;


	/**
	 * @param list<scalar|null|array<array-key, scalar|array<array-key, scalar|list<string>>>> $constructorParams
	 * @param literal-string $messageFormat Never build this from anything the checked host sends, it is used as a format and only the values are encoded when printed
	 * @param array<array-key, string|SecurityTxtHost> $messageValues A host is passed as one so it prints as it reads, like everywhere else. Stored as a list, see the constructor
	 * @param list<string> $redirects
	 * @throws Throwable
	 */
	public function __construct(
		private readonly array $constructorParams,
		private readonly string $messageFormat,
		array $messageValues,
		private readonly string $url,
		private readonly array $redirects = [],
		int $code = 0,
		?Throwable $previous = null,
	) {
		// Code always passes a list, but `SecurityTxtJson` replays whatever the serialized params hold, and a string key there is read as a named argument by the CLI, which
		// spreads these into a call
		$this->messageValues = array_values($messageValues);
		// `Exception::getMessage()` is final, so this is the only place the message can be made safe to display anywhere, terminal, log or page alike; `getMessageValues()`
		// still hands over what the host sent, for a caller that knows what it is rendering into
		parent::__construct(vsprintf($this->messageFormat, array_map(SecurityTxtPrintableValue::render(...), $this->messageValues)), $code, $previous);
	}


	/**
	 * A host as a constructor param has to be a scalar, because that is what a replay of stored JSON hands back, and this is the way back from one. Without it a host arrived
	 * as an object on a live check and as a string on a replay, and a string is encoded where a host reads as itself, so the same failure said `háčky.example` once and
	 * `h%C3%A1%C4%8Dky.example` the next time.
	 *
	 * The wire carries what `getUnicode()` writes, and `fromString()` takes exactly that and nothing else, but the two are not quite inverses: a punycode label whose payload
	 * decodes to characters that are not in normalization order, `xn--wuao` decodes to U+0352 U+0359 and NFC orders them the other way, comes back out of `getUnicode()` as a
	 * spelling that reparses to a different host, and `fromString()` refuses it. That host is unusual but a redirect can name one, so this keeps the string rather than throwing:
	 * a failure that reads encoded is what happened before any of this, while a replay that dies takes the whole stored result with it. The exceptions carrying a host accept
	 * both, so the string arm is a value they can hold.
	 */
	final protected static function toHost(string|SecurityTxtHost $host): string|SecurityTxtHost
	{
		if ($host instanceof SecurityTxtHost) {
			return $host;
		}
		try {
			return SecurityTxtHost::fromString($host);
		} catch (SecurityTxtCannotParseHostnameException) {
			return $host;
		}
	}


	/**
	 * The scalar a constructor param has to be, whichever arm `toHost()` returned.
	 */
	final protected static function hostToString(string|SecurityTxtHost $host): string
	{
		return $host instanceof SecurityTxtHost ? $host->getUnicode() : $host;
	}


	/**
	 * @return literal-string
	 */
	public function getMessageFormat(): string
	{
		return $this->messageFormat;
	}


	/**
	 * The ` (redirects: %s → %s)` part of a message, with one placeholder per redirect, empty when there was none.
	 *
	 * @param list<string> $redirects
	 * @param literal-string $suffix Added inside the brackets after the last redirect
	 * @return literal-string
	 */
	protected function getRedirectsFormat(array $redirects, string $suffix = ''): string
	{
		if ($redirects === []) {
			return '';
		}
		$format = ' (redirects: %s';
		for ($i = 1; $i < count($redirects); $i++) {
			$format .= ' → %s';
		}
		return $format . $suffix . ')';
	}


	/**
	 * @return list<string|SecurityTxtHost>
	 */
	public function getMessageValues(): array
	{
		return $this->messageValues;
	}


	public function getUrl(): string
	{
		return $this->url;
	}


	/**
	 * @return list<string>
	 */
	public function getRedirects(): array
	{
		return $this->redirects;
	}


	/**
	 * @return array<string, mixed>
	 */
	#[Override]
	public function jsonSerialize(): array
	{
		return [
			'class' => $this::class,
			'params' => $this->constructorParams,
			'message' => $this->getMessage(),
			'messageFormat' => $this->getMessageFormat(),
			'messageValues' => array_map(self::hostToString(...), $this->getMessageValues()),
			'url' => $this->getUrl(),
			'redirects' => $this->getRedirects(),
		];
	}

}
