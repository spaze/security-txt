<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Exception;
use JsonSerializable;
use Override;
use Spaze\SecurityTxt\SecurityTxtHost;
use Spaze\SecurityTxt\SecurityTxtPrintableValue;
use Throwable;
use Uri\WhatWg\Url;

abstract class SecurityTxtFetcherException extends Exception implements JsonSerializable
{

	/** @var list<string|Url|SecurityTxtHost> */
	private readonly array $messageValues;


	/**
	 * @param list<scalar|null|Url|SecurityTxtHost|array<array-key, scalar|array<array-key, scalar|list<string>>>> $constructorParams Passed as themselves, a URL and a host are put in the spelling the wire carries when this is serialized and not before, so no caller has to know one
	 * @param literal-string $messageFormat Never build this from anything the checked host sends, it is used as a format and only the values are encoded when printed
	 * @param array<array-key, string|Url|SecurityTxtHost> $messageValues A host and a URL are passed as themselves so each prints as it reads, like everywhere else. Stored as a list, see the constructor
	 * @param Url|null $url Null where there is none to name, which is what a hostname that would not parse leaves behind. Nullable but not optional, so a subclass with a URL to hand over cannot leave it out by saying nothing
	 * @param list<string> $redirects
	 * @throws Throwable
	 */
	public function __construct(
		private readonly array $constructorParams,
		private readonly string $messageFormat,
		array $messageValues,
		private readonly ?Url $url,
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
	 * @return literal-string
	 */
	public function getMessageFormat(): string
	{
		return $this->messageFormat;
	}


	/**
	 * A recorded chain as message values. The entries are URLs this library resolved and wrote down, so they print as URLs rather than as text a host sent, which is what a
	 * plain string in a message means.
	 *
	 * @param list<string> $redirects
	 * @return list<string|Url>
	 */
	protected function redirectValues(array $redirects): array
	{
		return array_map(fn(string $redirect): string|Url => Url::parse($redirect) ?? $redirect, $redirects);
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
	 * @return list<string|Url|SecurityTxtHost>
	 */
	public function getMessageValues(): array
	{
		return $this->messageValues;
	}


	public function getUrl(): ?Url
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
	 * The one place a stored URL or host is spelled. `SecurityTxtJson` reads the constructor back and turns the string into the object again, so what a subclass hands over is
	 * what its own constructor takes, and a spelling nobody writes is a spelling nobody can get wrong.
	 *
	 * @return array<string, mixed>
	 */
	#[Override]
	public function jsonSerialize(): array
	{
		return [
			'class' => $this::class,
			'params' => array_map($this->paramToWire(...), $this->constructorParams),
		];
	}


	/**
	 * Only a URL and a host are spelled, everything else is data and goes as it is: `SecurityTxtPrintableValue::render()` percent encodes a plain string, which is what makes it
	 * safe to print and exactly what would corrupt an IP address or a header value on the way to storage. Arrays are walked because a `Url` in one would otherwise reach
	 * `json_encode()` as an object with nothing public on it and be stored as `{}`.
	 */
	private function paramToWire(mixed $param): mixed
	{
		if ($param instanceof Url || $param instanceof SecurityTxtHost) {
			return SecurityTxtPrintableValue::render($param);
		}
		return is_array($param) ? array_map($this->paramToWire(...), $param) : $param;
	}

}
